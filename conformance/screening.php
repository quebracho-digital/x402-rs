<?php

declare(strict_types=1);

/*
 * Screening providers against scripted HTTP answers: TokenBlacklist (the token's own blacklist by eth_call),
 * ChainalysisOracle (on-chain sanctions oracle), ChainalysisApi, the Screening listener (allow and deny lists),
 * plus the list parsers (AddressList, OFAC's SDN.CSV). What PHP sends and what reason it gives is written to
 * vectors/screening.json. Run by export.sh.
 */

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Quebracho\X402\AddressCheck;
use Quebracho\X402\AddressList;
use Quebracho\X402\ChainalysisApi;
use Quebracho\X402\ChainalysisOracle;
use Quebracho\X402\Networks;
use Quebracho\X402\OfacSdn;
use Quebracho\X402\Screening;
use Quebracho\X402\ScreeningSkipped;
use Quebracho\X402\TokenBlacklist;

[$self, $lib, $out] = $argv + [null, null, null];
require $lib.'/vendor/autoload.php';

final class Down extends \RuntimeException implements ClientExceptionInterface
{
}

final class Script implements ClientInterface
{
    public array $sent = [];

    public function __construct(private array $answers)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $body = (string) $request->getBody();
        $this->sent[] = [
            'method' => $request->getMethod(),
            'url' => (string) $request->getUri(),
            'api_key' => $request->getHeaderLine('X-API-Key') ?: null,
            'body' => '' === $body ? null : json_decode($body, true),
        ];
        $a = array_shift($this->answers) ?? ['down' => true];
        if ($a['down'] ?? false) {
            throw new Down('connection refused');
        }

        return new Response($a['status'], $a['headers'] ?? ['Content-Type' => 'application/json'], $a['body']);
    }
}

$f = new Psr17Factory();
$base = Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD');
$payer = '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23';
$word = fn (int $v) => '0x'.str_pad(dechex($v), 64, '0', STR_PAD_LEFT);
$rpcOk = fn (string $result) => ['status' => 200, 'body' => json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $result])];
$rpcErr = ['status' => 200, 'body' => '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}'];
$api = fn (array $ids) => ['status' => 200, 'body' => json_encode(['identifications' => $ids])];

/** Runs one address through AddressCheck with only $listener after OFAC (off), as the library does. */
$run = function (callable $listener, string $address, array $req) {
    $skips = 0;
    $events = new class($listener, $skips) implements EventDispatcherInterface {
        public function __construct(private $listener, private int &$skips)
        {
        }

        public function dispatch(object $event): object
        {
            if ($event instanceof AddressCheck) {
                ($this->listener)($event);
            }
            if ($event instanceof ScreeningSkipped) {
                ++$this->skips;
            }

            return $event;
        }
    };
    $reason = AddressCheck::run($events, AddressCheck::PAYER, $address, $req, OfacSdn::off());

    return [$reason, $skips];
};

$cases = [];
$listeners = [
    'token_blacklist' => [
        'known USDC, not frozen' => [[$rpcOk($word(0))], [], $payer, $base],
        'known USDC, frozen' => [[$rpcOk($word(1))], [], $payer, $base],
        'node returns an error' => [[$rpcErr], [], $payer, $base],
        'node returns error null and a result' => [[['status' => 200, 'body' => json_encode(['jsonrpc' => '2.0', 'id' => 1, 'error' => null, 'result' => $word(1)])]], [], $payer, $base],
        'node down' => [[['down' => true]], [], $payer, $base],
        'node down, fail open' => [[['down' => true]], ['failOpen' => true], $payer, $base],
        'answer is not a word' => [[$rpcOk('0x1')], [], $payer, $base],
        'answer is not JSON-RPC' => [[['status' => 502, 'body' => 'Bad gateway']], [], $payer, $base],
        'token not known: not asked' => [[], [], $payer, ['asset' => '0x1111111111111111111111111111111111111111'] + $base],
        'token added by the caller (legacy USDT function)' => [[$rpcOk($word(1))], ['tokens' => ['eip155:84532|0x1111111111111111111111111111111111111111' => 'isBlackListed']], $payer, ['asset' => '0x1111111111111111111111111111111111111111'] + $base],
        'payer not an EVM address' => [[], [], 'alice.near', $base],
        'Ethereum mainnet USDT' => [[$rpcOk($word(0))], [], $payer, ['network' => 'eip155:1', 'asset' => '0xdAC17F958D2ee523a2206206994597C13D831ec7'] + $base],
    ],
    'chainalysis_oracle' => [
        'not sanctioned' => [[$rpcOk($word(0))], [], $payer, $base],
        'sanctioned' => [[$rpcOk($word(1))], [], $payer, $base],
        'node down' => [[['down' => true]], [], $payer, $base],
        'node down, fail open' => [[['down' => true]], ['failOpen' => true], $payer, $base],
        'own RPC endpoint' => [[$rpcOk($word(0))], ['rpc' => 'https://rpc.example.test/eth'], $payer, $base],
        'not an EVM address: not asked' => [[], [], 'alice.near', $base],
    ],
    'chainalysis_api' => [
        'not identified' => [[$api([])], [], $payer, $base],
        'identified' => [[$api([['category' => 'sanctions', 'name' => 'SANCTIONS: OFAC SDN']])], [], $payer, $base],
        'bad key (401): never fails open' => [[['status' => 401, 'body' => '{"message":"Unauthorized"}']], ['failOpen' => true], $payer, $base],
        'server error' => [[['status' => 500, 'body' => 'oops']], [], $payer, $base],
        'server error, fail open' => [[['status' => 500, 'body' => 'oops']], ['failOpen' => true], $payer, $base],
        'no identifications field' => [[['status' => 200, 'body' => '{"other":1}']], [], $payer, $base],
        'down' => [[['down' => true]], [], $payer, $base],
        'address with characters to encode' => [[$api([])], [], 'bc1q a/b?c', $base],
    ],
];
foreach ($listeners as $kind => $set) {
    foreach ($set as $name => [$answers, $opts, $address, $req]) {
        $client = new Script($answers);
        $listener = match ($kind) {
            'token_blacklist' => new TokenBlacklist($client, $f, $f, $opts['failOpen'] ?? false, $opts['tokens'] ?? []),
            'chainalysis_oracle' => new ChainalysisOracle($client, $f, $f, $opts['rpc'] ?? null, $opts['failOpen'] ?? false),
            'chainalysis_api' => new ChainalysisApi($client, $f, 'test-api-key', $opts['failOpen'] ?? false),
        };
        [$reason, $skips] = $run($listener, $address, $req);
        $cases[] = ['kind' => $kind, 'name' => $name, 'options' => (object) $opts, 'address' => $address, 'req' => $req, 'answers' => $answers, 'sent' => $client->sent, 'reason' => $reason, 'skipped' => $skips];
    }
}

// The Screening listener: allow and deny files, and the API when given.
$dir = sys_get_temp_dir().'/x402-screening-'.getmypid();
@mkdir($dir);
$listed = '0x000000000000000000000000000000000000bEEF';
foreach ([
    'not listed, no API' => [null, null, [], false],
    'denied' => [null, "# updated: 2026-11-01T00:00:00Z\n$listed  a note\n", [], false],
    'denied in another case' => [null, strtolower($listed)."\n", [], false],
    'allowed: the API is not asked' => [$listed."\n", null, [$api([['category' => 'sanctions']])], true],
    'allowed and denied: allow wins' => [$listed."\n", $listed."\n", [], false],
    'not listed, API says sanctioned' => [null, null, [$api([['category' => 'sanctions']])], true],
    'not listed, API clean' => [null, null, [$api([])], true],
] as $name => [$allow, $deny, $answers, $withApi]) {
    @unlink("$dir/allow.txt");
    @unlink("$dir/deny.txt");
    null === $allow || file_put_contents("$dir/allow.txt", $allow);
    null === $deny || file_put_contents("$dir/deny.txt", $deny);
    $client = new Script($answers);
    $screening = new Screening($dir, $withApi ? new ChainalysisApi($client, $f, 'test-api-key') : null);
    [$reason, $skips] = $run($screening, $listed, $base);
    $cases[] = ['kind' => 'screening', 'name' => $name, 'allow' => $allow, 'deny' => $deny, 'api' => $withApi, 'address' => $listed, 'req' => $base, 'answers' => $answers, 'sent' => $client->sent, 'reason' => $reason, 'skipped' => $skips];
}
@unlink("$dir/allow.txt");
@unlink("$dir/deny.txt");
@rmdir($dir);

// Parsers.
$lists = [];
foreach ([
    "# comment\n\n0x000000000000000000000000000000000000dEaD  note\n9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\nscam-example.near\n",
    "0xAbC0000000000000000000000000000000000001\r\n0xabc0000000000000000000000000000000000001\r\n  # indented comment\n\tspaced.near\textra\n",
    '',
] as $text) {
    $lists[] = ['text' => $text, 'addresses' => AddressList::parse($text), 'updated' => AddressList::updated($text)];
}
$dates = [];
foreach (['# updated: 2026-11-06 10:00:00', '# updated: 2026-11-06T19:33:18Z', '# UPDATED: 2026-11-06T19:33:18+00:00', '#updated:2026-11-06', '# updated: not-a-date', '# updated: 2026-11-06T19:33:18-03:00', 'no comment'] as $text) {
    $dates[] = ['text' => $text, 'updated' => AddressList::updated($text)];
}
$csv = implode("\n", [
    '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Havana, Cuba."',
    '9001,"SOMEONE",individual,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XBT 1AbcDefGhij.; Digital Currency Address - ETH 0x0330070FD38Ec3bB94F58FA55D40368271E9e54A; alt. Digital Currency Address - ETH 0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b."',
    '9002,"MULTI LINE",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Website example.org; Digital Currency Address - USDT',
    'TXyz123; Digital Currency Address - ETH 0x0330070FD38Ec3bB94F58FA55D40368271E9e54A."',
    '9003,"QUOTED ""NAME""",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XMR 4Abc"',
    '9004,"BROKEN MARKERS",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - ; Digital Currency Address - eth 0xab; Digital Currency Address - ETH; Digital Currency Address - TRX TCrlf1"'."\r",
    '9005,"SHORT ROW"',
    '9006,"ESCAPED",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"note ""q"", Digital Currency Address - XBT 1Escaped"',
    '9007,"MID QUOTE",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,Digital Currency Address - XBT 1Mid"q,trailing',
    '9008,"GLUED",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - ETH0xglued; Digital Currency Address -  0xdouble"',
    '9009,"TRAILING COMMA",-0- ,"CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XBT 1Last",',
]);
$sdn = ['csv' => $csv, 'addresses' => OfacSdn::parse($csv)];

$commit = (string) getenv('X402_COMMIT');
file_put_contents("$out/screening.json", json_encode(['source' => 'quebracho/x402'.('' !== $commit ? " @ $commit" : ''), 'generator' => 'conformance/screening.php', 'cases' => ['listeners' => $cases, 'lists' => $lists, 'dates' => $dates, 'sdn' => $sdn, 'rpc' => array_map(fn ($n) => ['network' => $n, 'rpc' => Networks::find($n)['rpc'] ?? null], ['eip155:1', 'eip155:8453', 'eip155:84532', 'eip155:5042', 'eip155:5042002', 'eip155:11155111', 'eip155:43113', 'eip155:80002']), 'tokens' => TokenBlacklist::TOKENS, 'functions' => TokenBlacklist::FUNCTIONS]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR)."\n");
echo 'screening.json: '.count($cases)." listener cases\n";
