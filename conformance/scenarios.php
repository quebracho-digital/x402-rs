<?php

declare(strict_types=1);

/*
 * Sale scenarios: scripted requests run through the PHP X402Middleware with a scripted facilitator,
 * handler and ledger. What PHP answers (status, error, headers, which callbacks ran, the outcome events and
 * the ledger afterwards) is written to vectors/sale.json; the Rust seller must answer the same.
 *
 * Run by export.sh after export.php.
 */

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Quebracho\X402\AddressCheck;
use Quebracho\X402\Authorization;
use Quebracho\X402\EvmExact;
use Quebracho\X402\Facilitator;
use Quebracho\X402\FacilitatorException;
use Quebracho\X402\LedgerUnavailableException;
use Quebracho\X402\Networks;
use Quebracho\X402\OfacSdn;
use Quebracho\X402\PaymentFault;
use Quebracho\X402\PaymentHeaders;
use Quebracho\X402\PaymentLedger;
use Quebracho\X402\PaymentOutcome;
use Quebracho\X402\Signer;
use Quebracho\X402\Stop;
use Quebracho\X402\X402Middleware;

[$self, $lib, $out] = $argv + [null, null, null];
require $lib.'/vendor/autoload.php';

const NOW = 1_800_000_000;
const BUYER = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const PAY_TO = '0x000000000000000000000000000000000000dEaD';

/** A ledger in memory, whose operations can be made to fail (LedgerUnavailableException) per step. */
final class ScriptedLedger implements PaymentLedger
{
    public array $states = [];
    public array $open = [];
    /** @var list<array{op: string, status?: string}> */
    public array $fail = [];

    private function failing(string $op, ?array $state = null): void
    {
        foreach ($this->fail as $f) {
            if ($f['op'] === $op && (!isset($f['status']) || ($state['status'] ?? null) === $f['status'])) {
                throw new LedgerUnavailableException("scripted $op failure");
            }
        }
    }

    public function claim(string $key, int $ttl): bool
    {
        $this->failing('claim');
        if (isset($this->states[$key])) {
            return false;
        }
        $this->states[$key] = ['status' => 'claimed'];

        return true;
    }

    public function get(string $key): ?array
    {
        $this->failing('get');

        return $this->states[$key] ?? null;
    }

    public function put(string $key, array $state, int $ttl): void
    {
        $this->failing('put', $state);
        $this->states[$key] = $state;
    }

    public function release(string $key): void
    {
        $this->failing('release');
        unset($this->states[$key], $this->open[$key]);
    }

    public function open(string $key, array $ref, int $ttl): void
    {
        $this->failing('open');
        $this->open[$key] = $ref;
    }

    public function openKeys(int $limit): array
    {
        return array_slice($this->open, 0, $limit, true);
    }

    public function close(string $key): void
    {
        $this->failing('close');
        unset($this->open[$key]);
    }
}

/** A facilitator that answers from the step's script and counts its calls. */
final class ScriptedFacilitator implements Facilitator
{
    public mixed $verify = null;
    public mixed $settle = 'mock';
    public int $verifies = 0;
    public int $settles = 0;

    public function verify(array $payment, array $req): array
    {
        ++$this->verifies;

        return match (true) {
            'unavailable' === $this->verify => throw new FacilitatorException('scripted: down'),
            'throw' === $this->verify => throw new \RuntimeException('scripted: broken'),
            null === $this->verify => ['isValid' => true],
            default => ['isValid' => false, 'invalidReason' => $this->verify],
        };
    }

    public function settle(array $payment, array $req): array
    {
        ++$this->settles;

        return match (true) {
            'unavailable' === $this->settle => throw new FacilitatorException('scripted: down'),
            'throw' === $this->settle => throw new \RuntimeException('scripted: broken'),
            'mock' === $this->settle => ['success' => true, 'transaction' => '0x'.str_repeat('ab', 32), 'network' => $req['network'], 'payer' => $payment['payload']['authorization']['from'] ?? null],
            default => $this->settle,
        };
    }
}

$req = Networks::requirements('eip155:84532', '0.01', PAY_TO);
$upfrontReq = $req;
$upfrontReq['extra']['paymentFlow'] = 'upfront';
$buyer = new Signer(BUYER);
$pay = function (array $req, string $nonce, array $auth = []) use ($buyer): array {
    $p = Authorization::pay($buyer, ['x402Version' => 2, 'resource' => ['url' => 'https://device.test/reading'], 'accepts' => [$req]], $req, NOW, $nonce);
    if ([] !== $auth) {
        $p['payload']['authorization'] = $auth + $p['payload']['authorization'];
        $p['payload']['signature'] = $buyer->sign(Authorization::digest($req, $p['payload']['authorization']));
    }

    return $p;
};
$nonce = fn (int $i) => '0x'.str_pad(dechex($i), 64, '0', STR_PAD_LEFT);
$header = fn (array $p) => PaymentHeaders::encode($p);

// A snapshot that lists the buyer, newer than the shipped one, for the sanctions scenario.
$sanctioned = sys_get_temp_dir().'/x402-scenario-ofac.json';
file_put_contents($sanctioned, json_encode(['published' => '2999-01-01T00:00:00Z', 'addresses' => ['ETH' => [$buyer->address()]]]));
$stopFile = sys_get_temp_dir().'/x402-scenario-'.getmypid().'/stop';
@mkdir(dirname($stopFile), 0700, true);

$valid = fn (int $i, array $r = []) => ['header' => $header($pay([] === $r ? $req : $r, $nonce($i)))];
$ok = ['status' => 200, 'body' => '{"reading":21.5}'];

// Each scenario: offers, options and steps. A step: header (or none), handler, verify, settle, lookup, stop, fail, keep.
$scenarios = [
    ['name' => 'no payment: 402 with the offer', 'steps' => [['handler' => $ok]]],
    ['name' => 'header not base64 JSON: 400', 'steps' => [['header' => '%%%', 'handler' => $ok]]],
    ['name' => 'payment for an offer not made: 402', 'steps' => [['header' => $header($pay(['network' => 'eip155:8453'] + $req, $nonce(1))), 'handler' => $ok]]],
    ['name' => 'paid: delivered once, the retry is replayed', 'steps' => [$valid(2) + ['handler' => $ok], $valid(2) + ['handler' => $ok]]],
    ['name' => 'a second payment with another nonce runs again', 'steps' => [$valid(3) + ['handler' => $ok], $valid(4) + ['handler' => $ok]]],
    ['name' => 'tampered amount: refused offline', 'steps' => [['header' => $header(array_replace_recursive($pay($req, $nonce(5)), ['payload' => ['authorization' => ['value' => '1']]])), 'handler' => $ok]]],
    ['name' => 'handler fails: not charged, claim freed, the retry runs', 'steps' => [$valid(6) + ['handler' => ['status' => 500, 'body' => 'boom']], $valid(6) + ['handler' => $ok]]],
    ['name' => 'handler throws: not charged, the retry runs', 'steps' => [$valid(7) + ['handler' => ['throw' => true]], $valid(7) + ['handler' => $ok]]],
    ['name' => 'online verify refuses: nothing claimed or run', 'steps' => [$valid(8) + ['handler' => $ok, 'verify' => 'insufficient_funds'], $valid(8) + ['handler' => $ok]]],
    ['name' => 'online verify unreachable: 502', 'steps' => [$valid(9) + ['handler' => $ok, 'verify' => 'unavailable']]],
    ['name' => 'online verify throws: unexpected_verify_error', 'steps' => [$valid(10) + ['handler' => $ok, 'verify' => 'throw']]],
    ['name' => 'settle refused clearly: withheld, claim freed', 'steps' => [$valid(11) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'insufficient_funds']], $valid(11) + ['handler' => $ok]]],
    ['name' => 'settle pending with a transaction: kept, the retry is settlement_pending', 'steps' => [
        $valid(12) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'settlement_pending', 'transaction' => '0x'.str_repeat('cd', 32)]],
        $valid(12) + ['handler' => $ok],
    ]],
    ['name' => 'pending, then the lookup confirms: replayed', 'steps' => [
        $valid(13) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'settlement_pending', 'transaction' => '0x'.str_repeat('cd', 32)]],
        $valid(13) + ['handler' => $ok, 'lookup' => ['success' => true, 'transaction' => '0x'.str_repeat('cd', 32), 'network' => 'eip155:84532']],
    ]],
    ['name' => 'pending, then the lookup refutes: runs as new', 'steps' => [
        $valid(14) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'settlement_pending', 'transaction' => '0x'.str_repeat('cd', 32)]],
        $valid(14) + ['handler' => $ok, 'lookup' => ['success' => false]],
    ]],
    ['name' => 'pending, the lookup names another transaction: still pending', 'steps' => [
        $valid(15) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'settlement_pending', 'transaction' => '0x'.str_repeat('cd', 32)]],
        $valid(15) + ['handler' => $ok, 'lookup' => ['success' => true, 'transaction' => '0x'.str_repeat('ee', 32), 'network' => 'eip155:84532']],
    ]],
    ['name' => 'facilitator down on settle: 502, claim kept', 'steps' => [$valid(16) + ['handler' => $ok, 'settle' => 'unavailable'], $valid(16) + ['handler' => $ok]]],
    ['name' => 'settle throws: kept as unexpected_settle_error', 'steps' => [$valid(17) + ['handler' => $ok, 'settle' => 'throw'], $valid(17) + ['handler' => $ok]]],
    ['name' => 'ledger refuses the settling write: 503, withheld, freed', 'steps' => [$valid(18) + ['handler' => $ok, 'fail' => [['op' => 'put', 'status' => 'settling']]], $valid(18) + ['handler' => $ok]]],
    ['name' => 'ledger down before anything: 503', 'steps' => [$valid(19) + ['handler' => $ok, 'fail' => [['op' => 'get']]]]],
    ['name' => 'ledger loses the outcome after a settle: answer still goes out', 'steps' => [$valid(20) + ['handler' => $ok, 'fail' => [['op' => 'put', 'status' => 'delivered']]], $valid(20) + ['handler' => $ok]]],
    ['name' => 'sensitive: delivered, the retry gets already_settled', 'steps' => [$valid(21) + ['handler' => $ok, 'keep' => false], $valid(21) + ['handler' => $ok]]],
    ['name' => 'stop engaged: paused before anything', 'steps' => [$valid(22) + ['handler' => $ok, 'stop' => true], ['handler' => $ok, 'stop' => true]]],
    ['name' => 'stop engaged: a delivered payment is still replayed', 'steps' => [$valid(23) + ['handler' => $ok], $valid(23) + ['handler' => $ok, 'stop' => true]]],
    ['name' => 'sanctioned payer', 'ofac' => 'sanctioned', 'steps' => [$valid(24) + ['handler' => $ok]]],
    ['name' => 'a listener rejects the payer', 'deny' => 'address_denied', 'steps' => [$valid(25) + ['handler' => $ok]]],
    ['name' => 'upfront: settled before the handler', 'offers' => [$upfrontReq], 'steps' => [$valid(26, $upfrontReq) + ['handler' => $ok], $valid(26, $upfrontReq) + ['handler' => $ok]]],
    ['name' => 'upfront: settle fails, handler never runs', 'offers' => [$upfrontReq], 'steps' => [$valid(27, $upfrontReq) + ['handler' => $ok, 'settle' => ['success' => false, 'errorReason' => 'insufficient_funds']]]],
    ['name' => 'upfront: handler fails after the settle, the retry runs it without a second settle', 'offers' => [$upfrontReq], 'steps' => [
        $valid(28, $upfrontReq) + ['handler' => ['status' => 500, 'body' => 'relay stuck']],
        $valid(28, $upfrontReq) + ['handler' => $ok],
        $valid(28, $upfrontReq) + ['handler' => $ok],
    ]],
    ['name' => 'upfront: handling write refused, handler not run', 'offers' => [$upfrontReq], 'steps' => [$valid(29, $upfrontReq) + ['handler' => $ok, 'fail' => [['op' => 'put', 'status' => 'handling']]], $valid(29, $upfrontReq) + ['handler' => $ok]]],
    ['name' => 'a claim in progress: 409', 'preset' => ['claimed'], 'steps' => [$valid(30) + ['handler' => $ok]]],
    ['name' => 'settling without a reference: settlement_unknown', 'preset' => ['settling'], 'steps' => [$valid(30) + ['handler' => $ok]]],
    ['name' => 'handling without a response: needs_review', 'preset' => ['handling'], 'steps' => [$valid(30) + ['handler' => $ok]]],
    ['name' => 'two offers on one network: picked by asset', 'offers' => [['asset' => '0x1111111111111111111111111111111111111111'] + $req, $req], 'steps' => [$valid(31) + ['handler' => $ok]]],
];

final class ScriptedHandler implements RequestHandlerInterface
{
    public int $calls = 0;

    public function __construct(private readonly array $script)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ++$this->calls;
        if ($this->script['throw'] ?? false) {
            throw new \RuntimeException('scripted handler failure');
        }

        return new Response($this->script['status'], ['Content-Type' => 'application/json'], $this->script['body']);
    }
}

$cases = [];
$f = new Psr17Factory();
foreach ($scenarios as $scenario) {
    $offers = $scenario['offers'] ?? [$req];
    $ledger = new ScriptedLedger();
    foreach ($scenario['preset'] ?? [] as $status) {
        // The key of the step's payment (nonce 30), in the given state.
        $ledger->states[\Quebracho\X402\Settlement::key($pay($req, $nonce(30)))] = ['status' => $status];
    }
    $facilitator = new ScriptedFacilitator();
    $outcomes = [];
    $events = new class($outcomes, $scenario['deny'] ?? null) implements EventDispatcherInterface {
        public function __construct(private array &$outcomes, private readonly ?string $deny)
        {
        }

        public function dispatch(object $event): object
        {
            if ($event instanceof PaymentOutcome) {
                $this->outcomes[] = ['status' => $event->status, 'reason' => $event->reason];
            }
            if ($event instanceof PaymentFault) {
                $this->outcomes[] = ['status' => 'fault', 'reason' => $event->op];
            }
            if ($event instanceof AddressCheck && null !== $this->deny) {
                $event->reject($this->deny);
            }

            return $event;
        }
    };
    $lookup = null;
    $steps = [];
    foreach ($scenario['steps'] as $step) {
        $facilitator->verify = $step['verify'] ?? null;
        $facilitator->settle = $step['settle'] ?? 'mock';
        $ledger->fail = $step['fail'] ?? [];
        $stepLookup = $step['lookup'] ?? null;
        ($step['stop'] ?? false) ? touch($stopFile) : @unlink($stopFile);
        $handler = new ScriptedHandler($step['handler']);
        $outcomes = [];
        $keep = $step['keep'] ?? true;
        $mw = new X402Middleware(
            [new EvmExact(clock: fn () => NOW)],
            fn () => $offers,
            fn () => throw new \LogicException('claims come from the ledger'),
            $f, $f, $facilitator,
            events: $events,
            resource: fn () => ['url' => 'https://device.test/reading'],
            ledger: $ledger,
            lookup: null === $stepLookup ? null : fn () => $stepLookup,
            sensitive: fn () => !$keep,
            ofac: 'sanctioned' === ($scenario['ofac'] ?? null) ? new OfacSdn($sanctioned) : null,
            stop: new Stop($stopFile),
        );
        [$v0, $s0] = [$facilitator->verifies, $facilitator->settles];
        $request = new ServerRequest('GET', 'https://device.test/reading');
        if (isset($step['header'])) {
            $request = $request->withHeader('PAYMENT-SIGNATURE', $step['header']);
        }
        try {
            $response = $mw->process($request, $handler);
            $result = [
                'status' => $response->getStatusCode(),
                'body' => (string) $response->getBody(),
                'payment_required' => '' === $response->getHeaderLine('PAYMENT-REQUIRED') ? null : PaymentHeaders::decode($response->getHeaderLine('PAYMENT-REQUIRED')),
                'payment_response' => '' === $response->getHeaderLine('PAYMENT-RESPONSE') ? null : PaymentHeaders::decode($response->getHeaderLine('PAYMENT-RESPONSE')),
                'retry_after' => '' === $response->getHeaderLine('Retry-After') ? null : $response->getHeaderLine('Retry-After'),
            ];
        } catch (\RuntimeException $e) {
            $result = ['threw' => true];
        }
        $ledgerView = [];
        foreach ($ledger->states as $key => $state) {
            $ledgerView[$key] = [
                'status' => $state['status'],
                'response' => isset($state['response']),
                'handler_ran' => $state['handler_ran'] ?? null,
                'receipt_success' => $state['receipt']['success'] ?? null,
            ];
        }
        ksort($ledgerView);
        $open = array_keys($ledger->open);
        sort($open);
        $steps[] = [
            'step' => $step + ['lookup' => $stepLookup],
            'result' => $result,
            'handler_calls' => $handler->calls,
            'verify_calls' => $facilitator->verifies - $v0,
            'settle_calls' => $facilitator->settles - $s0,
            'outcomes' => $outcomes,
            'ledger' => (object) $ledgerView,
            'open' => $open,
        ];
    }
    @unlink($stopFile);
    $cases[] = ['name' => $scenario['name'], 'now' => NOW, 'offers' => $offers, 'resource' => ['url' => 'https://device.test/reading'], 'ofac' => $scenario['ofac'] ?? null, 'sanctioned' => 'sanctioned' === ($scenario['ofac'] ?? null) ? [$buyer->address()] : [], 'deny' => $scenario['deny'] ?? null, 'preset' => array_map(fn ($s) => ['key' => \Quebracho\X402\Settlement::key($pay($req, $nonce(30))), 'status' => $s], $scenario['preset'] ?? []), 'steps' => $steps];
}
@unlink($sanctioned);
@rmdir(dirname($stopFile));

$commit = (string) getenv('X402_COMMIT');
file_put_contents("$out/sale.json", json_encode(['source' => 'quebracho/x402'.('' !== $commit ? " @ $commit" : ''), 'generator' => 'conformance/scenarios.php', 'cases' => $cases], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR)."\n");
echo 'sale.json: '.count($cases)." scenarios\n";
