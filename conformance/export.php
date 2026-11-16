<?php

declare(strict_types=1);

/*
 * Exports conformance vectors from the PHP library quebracho/x402.
 *
 * Every expected value in conformance/vectors/ comes out of the PHP code, never
 * from a hand-written constant: the Rust core must reproduce them byte for byte.
 *
 * Usage: conformance/export.sh (runs this in Docker; no PHP on the host needed).
 */

use Quebracho\X402\Authorization;
use Quebracho\X402\Eip712;
use Quebracho\X402\EvmExact;
use Quebracho\X402\Field;
use Quebracho\X402\Networks;
use Quebracho\X402\Signer;
use Quebracho\X402\Settlement;
use Quebracho\X402\FacilitatorException;
use Quebracho\X402\Facilitator;

[$self, $lib, $out] = $argv + [null, null, null];
if (null === $lib || null === $out) {
    fwrite(STDERR, "usage: php export.php <path to quebracho/x402> <output dir>\n");
    exit(2);
}
require $lib.'/vendor/autoload.php';

const NOW = 1_800_000_000;
const BUYER = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const NONCE = '0x6a1f3e4b5c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071';
const SECP256K1_N = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

function write(string $dir, string $name, array $data): void
{
    @mkdir($dir, 0o755, true);
    $commit = (string) getenv('X402_COMMIT');
    $doc = ['source' => 'quebracho/x402'.('' !== $commit ? " @ $commit" : ''), 'generator' => 'conformance/export.php', 'cases' => $data];
    file_put_contents("$dir/$name.json", json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR)."\n");
    echo "$name.json: ".count($data)." cases\n";
}

// --- keccak: hashing of raw strings (type strings included, so no hash is typed by hand) ---
$keccak = [];
foreach ([
    '',
    'cow',
    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
    'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
    'ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
] as $s) {
    $keccak[] = ['input' => $s, 'hash' => Eip712::keccak($s)];
}
write($out, 'keccak', $keccak);

// --- field: the one spelling of each value ---
$addr = '0x'.str_repeat('aB', 20);
$b32 = '0x'.str_repeat('0f', 32);
$sig = '0x'.str_repeat('1c', 65);
$candidates = [
    Field::ADDRESS => [$addr, strtolower($addr), substr($addr, 2), '0X'.substr($addr, 2), $addr."\n", $addr.'0', substr($addr, 0, -1), '0x'.str_repeat('g', 40), '', ' '.$addr],
    Field::BYTES32 => [$b32, strtoupper($b32), '0x'.strtoupper(substr($b32, 2)), substr($b32, 2), $b32."\n", '0x'.str_repeat('0', 63), '0x'.str_repeat('0', 65), 'zz'],
    Field::SIGNATURE => [$sig, $sig.'00', substr($sig, 0, -2), $sig."\n", substr($sig, 2)],
    Field::PRIVATE_KEY => [BUYER, substr(BUYER, 2), BUYER."\n"],
    Field::UINT256 => ['0', '1', '10000', '010000', '00', '-1', '+1', '1e3', '0x10', ' 1', '1 ', "1\n", '١', str_repeat('9', 78), str_repeat('9', 79), ''],
    Field::AMOUNT => ['1', '10000', '0', '01', '-1', '', '1.5', str_repeat('9', 78), str_repeat('9', 79)],
    Field::TIMESTAMP => ['0', '1800000000', '01', str_repeat('9', 19), str_repeat('9', 20), '-5', '1.0'],
    Field::PAYMENT_ID => ['pay_123', 'A-z_09', str_repeat('a', 128), str_repeat('a', 129), '', '../../admin', 'a/b', 'a b', "a\n", 'ñ'],
    Field::EVM_NETWORK => ['eip155:1', 'eip155:84532', 'eip155:4689', 'eip155:0', 'eip155:01', 'eip155:', 'EIP155:1', 'eip155:1 ', 'solana:abc'],
];
$field = [];
foreach ($candidates as $rule => $values) {
    foreach ($values as $v) {
        $field[] = ['rule' => $rule, 'value' => $v, 'ok' => Field::is($rule, $v)];
    }
}
write($out, 'field', $field);

// --- signer: key -> EIP-55 address, and checksum spelling ---
$signer = [];
foreach ([BUYER, Eip712::keccak('cow'), '0x'.str_repeat('42', 32), '0x'.str_repeat('00', 31).'01'] as $key) {
    $signer[] = ['test_signer' => $key, 'address' => (new Signer($key))->address()];
}
$checksum = [];
foreach (['0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', '0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359', '0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb', '0x0000000000000000000000000000000000000000', strtolower((new Signer(BUYER))->address())] as $a) {
    $checksum[] = ['input' => $a, 'checksum' => Signer::checksum($a)];
}
write($out, 'signer', ['keys' => $signer, 'checksum' => $checksum]);

// --- digest: EIP-3009 TransferWithAuthorization against a requirement ---
$reqs = [
    'base-sepolia' => Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD'),
    'base' => Networks::requirements('eip155:8453', '1.5', '0x000000000000000000000000000000000000dEaD'),
    // Domain math only: chain 4689 with a placeholder token. Not a claim about IoTeX's USDC.
    'chain-4689-placeholder' => ['scheme' => 'exact', 'network' => 'eip155:4689', 'amount' => '250000', 'asset' => '0x1111111111111111111111111111111111111111', 'payTo' => '0x2222222222222222222222222222222222222222', 'maxTimeoutSeconds' => 300, 'extra' => ['name' => 'Placeholder', 'version' => '1']],
];
$digest = [];
foreach ($reqs as $name => $req) {
    foreach ([
        'pay' => ['from' => (new Signer(BUYER))->address(), 'to' => $req['payTo'], 'value' => $req['amount'], 'validAfter' => '0', 'validBefore' => (string) (NOW + 300), 'nonce' => NONCE],
        'max-values' => ['from' => (new Signer(BUYER))->address(), 'to' => $req['payTo'], 'value' => '115792089237316195423570985008687907853269984665640564039457584007913129639935', 'validAfter' => '9999999999999999999', 'validBefore' => '9999999999999999999', 'nonce' => '0x'.str_repeat('ff', 32)],
    ] as $variant => $auth) {
        $d = Authorization::digest($req, $auth);
        $digest[] = ['name' => "$name/$variant", 'req' => $req, 'authorization' => $auth, 'digest' => $d, 'signature' => (new Signer(BUYER))->sign($d), 'signer' => (new Signer(BUYER))->address()];
    }
}
write($out, 'digest', $digest);

// --- recover: ecrecover with low-s only ---
$d = $digest[0]['digest'];
$good = $digest[0]['signature'];
$hex = substr($good, 2);
$r = substr($hex, 0, 64);
$s = substr($hex, 64, 64);
$v = substr($hex, 128, 2);
$highS = str_pad(gmp_strval(gmp_sub(gmp_init(SECP256K1_N, 16), gmp_init($s, 16)), 16), 64, '0', STR_PAD_LEFT);
$flipV = '1b' === $v ? '1c' : '1b';
$recover = [];
foreach ([
    'good' => $good,
    'good, upper-case hex' => '0x'.strtoupper($hex),
    'v flipped' => "0x$r$s$flipV",
    'high s (malleated)' => "0x$r$highS$flipV",
    'v = 0' => "0x$r{$s}00",
    'v = 1' => "0x$r{$s}01",
    'v = 29' => "0x$r{$s}1d",
    'r = 0' => '0x'.str_repeat('0', 64).$s.$v,
    's = 0' => "0x$r".str_repeat('0', 64).$v,
    'r = n' => '0x'.strtolower(SECP256K1_N).$s.$v,
    'all zeros' => '0x'.str_repeat('00', 65),
    'too short' => substr($good, 0, -2),
    'no 0x' => $hex,
] as $name => $signature) {
    $recover[] = ['name' => $name, 'digest' => $d, 'signature' => $signature, 'address' => Signer::recover($d, $signature)];
}
// The spec "Mail" example: digest from the EIP-712 spec, key keccak('cow').
$recover[] = ['name' => 'eip-712 spec Mail', 'digest' => '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2', 'signature' => '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c', 'address' => Signer::recover('0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2', '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c')];
write($out, 'recover', $recover);

// --- evm_exact: EvmExact::verify reason codes (mirrors tests/EvmExactTest.php) ---
$req = Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD');
$payment = function (array $auth = [], ?Signer $by = null) use ($req): array {
    $p = Authorization::pay(new Signer(BUYER), ['x402Version' => 2, 'resource' => ['url' => 'https://example.test/mcp'], 'accepts' => [$req]], $req, NOW, NONCE);
    if ([] !== $auth || null !== $by) {
        $p['payload']['authorization'] = $auth + $p['payload']['authorization'];
        $p['payload']['signature'] = ($by ?? new Signer(BUYER))->sign(Authorization::digest($req, $p['payload']['authorization']));
    }

    return $p;
};
$base = $payment();
$cases = [];
$add = function (string $name, array $p, array $rq = [], int $now = NOW) use (&$cases, $req): void {
    $rq = [] === $rq ? $req : $rq;
    $cases[] = ['name' => $name, 'now' => $now, 'payment' => $p, 'req' => $rq, 'reason' => (new EvmExact(clock: fn () => $now))->verify($p, $rq)];
};
$patch = fn (array $with) => array_replace_recursive($base, $with);

$add('accepts its own payment', $base);
$add('amount', $patch(['payload' => ['authorization' => ['value' => '1']]]));
$add('recipient', $patch(['payload' => ['authorization' => ['to' => '0x0000000000000000000000000000000000000001']]]));
$add('payer', $patch(['payload' => ['authorization' => ['from' => '0x0000000000000000000000000000000000000001']]]));
$add('network', $patch(['accepted' => ['network' => 'eip155:7']]));
$add('array nonce', $patch(['payload' => ['authorization' => ['nonce' => ['x']]]]));
$add('echoed payTo', $patch(['accepted' => ['payTo' => '0x0000000000000000000000000000000000000001']]));
$add('echoed asset', $patch(['accepted' => ['asset' => '0x0000000000000000000000000000000000000001']]));
$add('echoed amount', $patch(['accepted' => ['amount' => '9']]));
$add('echoed asset, other case', $patch(['accepted' => ['asset' => strtolower($req['asset'])]]));
$add('version', $patch(['x402Version' => 1]));
$add('version as a string', $patch(['x402Version' => '2']));
$add('version as a float', $patch(['x402Version' => 2.0]));
$add('scheme', $patch(['accepted' => ['scheme' => 'upto']]));
$add('nonce without 0x', $patch(['payload' => ['authorization' => ['nonce' => substr(NONCE, 2)]]]));
$add('nonce not hex', $patch(['payload' => ['authorization' => ['nonce' => 'zz']]]));
$add('nonce upper-case, same bytes', $patch(['payload' => ['authorization' => ['nonce' => '0x'.strtoupper(substr(NONCE, 2))]]]));
$add('validAfter not decimal', $patch(['payload' => ['authorization' => ['validAfter' => '0abc']]]));
$add('validAfter as a number', $patch(['payload' => ['authorization' => ['validAfter' => 0]]]));
$add('value with a leading zero', $patch(['payload' => ['authorization' => ['value' => '010000']]]));
$add('signature not a string', $patch(['payload' => ['signature' => 42]]));
$add('signature with a trailing newline', $patch(['payload' => ['signature' => $base['payload']['signature']."\n"]]));
$add('smart-wallet signature', $patch(['payload' => ['signature' => $base['payload']['signature'].str_repeat('ab', 32).'6492649264926492649264926492649264926492649264926492649264926492']]));
$noAuth = $base;
unset($noAuth['payload']['authorization']);
$add('no authorization', $noAuth);
$noAccepted = $base;
unset($noAccepted['accepted']);
$add('no accepted', $noAccepted);
$add('validAfter in the future', $payment(['validAfter' => (string) (NOW + 1)]));
$add('validAfter now', $payment(['validAfter' => (string) NOW]));
foreach ([0, 1, EvmExact::SLACK - 1, EvmExact::SLACK] as $after) {
    $add("validBefore now + $after", $payment(['validBefore' => (string) (NOW + $after)]));
}
$other = new Signer('0x'.str_repeat('42', 32));
$add('signed by another key', $payment([], $other));
$add('another key signing as itself', $payment(['from' => $other->address()], $other));
$add('expired', $base, [], NOW + 3600);
$add('about to expire', $base, [], (int) $base['payload']['authorization']['validBefore'] - 5);
$noVersion = $req;
unset($noVersion['extra']['version']);
$add('requirements without the token version', $base, $noVersion);
$sig = substr($base['payload']['signature'], 2);
$highS = str_pad(gmp_strval(gmp_sub(gmp_init(SECP256K1_N, 16), gmp_init(substr($sig, 64, 64), 16)), 16), 64, '0', STR_PAD_LEFT);
$add('high-s signature', $patch(['payload' => ['signature' => '0x'.substr($sig, 0, 64).$highS.('1b' === substr($sig, 128, 2) ? '1c' : '1b')]]));
$long = $base;
$long['payload']['authorization']['validBefore'] = '99999999999';
$add('validity longer than the offer', $long);
foreach (['0', '', '-1', '1e3', '01'] as $amount) {
    $add("offer amount '$amount'", $base, ['amount' => $amount] + $req);
}
$add('offer payTo not canonical', $base, ['payTo' => substr($req['payTo'], 2)] + $req);
// PHP's loose casts on our own offer and on the buyer's echo: (string), (int) and empty() on every JSON type.
$withExtra = fn (string $field, mixed $v) => ['extra' => [$field => $v] + $req['extra']] + $req;
foreach (['"0"' => '0', '0' => 0, '0.0' => 0.0, '[]' => [], '["x"]' => ['x'], 'true' => true, '1.5' => 1.5, '1e20' => 1e20, '1e-5' => 1.0e-5, '"USDC "' => 'USDC ', 'null' => null] as $label => $v) {
    $add("offer extra.name $label", $base, $withExtra('name', $v));
    $add("offer extra.version $label", $base, $withExtra('version', $v));
}
foreach (['10000 (int)' => 10000, '10000.0' => 10000.0, '"10000.0"' => '10000.0', 'true' => true, '["10000"]' => ['10000'], 'null' => null] as $label => $v) {
    $add("offer amount $label", $base, ['amount' => $v] + $req);
    $add("echoed amount $label", $patch(['accepted' => ['amount' => $v]]));
}
foreach (['"300"' => '300', '"300abc"' => '300abc', '" 300"' => ' 300', '"1e3"' => '1e3', '"-5"' => '-5', 'true' => true, 'null' => null, '300.9' => 300.9, '[]' => [], '[1]' => [1], '"99999999999999999999"' => '99999999999999999999', '"+7"' => '+7', '"0x1A"' => '0x1A', '"2.5e2"' => '2.5e2'] as $label => $v) {
    $add("offer maxTimeoutSeconds $label", $base, ['maxTimeoutSeconds' => $v] + $req);
}
$add('offer network not EVM spelling', $patch(['accepted' => ['network' => 'eip155:084532']]), ['network' => 'eip155:084532'] + $req);
$add('echoed asset as a number', $patch(['accepted' => ['asset' => 123]]));
$add('offer asset as a number', $base, ['asset' => 123] + $req);
$add('offer payTo as an array', $base, ['payTo' => ['x']] + $req);
$add('offer amount false', $base, ['amount' => false] + $req);
$add('echoed amount false', $patch(['accepted' => ['amount' => false]]));
$add('echoed payTo true', $patch(['accepted' => ['payTo' => true]]));
write($out, 'evm_exact', $cases);

// --- settlement: reading a facilitator's answers without trusting their shape ---
$tx = '0x'.str_repeat('ab', 32);
$settledCases = [];
foreach ([
    'full' => ['success' => true, 'transaction' => $tx, 'network' => 'eip155:84532', 'payer' => '0xAb', 'errorReason' => 'r', 'errorMessage' => 'm', 'paymentId' => 'p1', 'amount' => '10000', 'extensions' => ['a' => 1]],
    'wrong types dropped' => ['success' => true, 'transaction' => 5, 'network' => ['x'], 'payer' => 7, 'errorReason' => false, 'amount' => '1e3', 'paymentId' => 9],
    'payer null kept' => ['success' => true, 'payer' => null],
    'amount not digits' => ['success' => true, 'amount' => '-5'],
    'amount empty' => ['success' => true, 'amount' => ''],
    'extensions null kept' => ['success' => true, 'extensions' => null],
    'nothing' => ['success' => true],
] as $name => $receipt) {
    $settledCases[] = ['name' => $name, 'receipt' => $receipt, 'settled' => Settlement::settled($receipt)];
}
$req84532 = ['network' => 'eip155:84532'];
$runCases = [];
foreach ([
    'success' => ['answer' => ['success' => true, 'transaction' => $tx, 'network' => 'eip155:84532']],
    'refused with reason' => ['answer' => ['success' => false, 'errorReason' => 'insufficient_funds']],
    'refused with a transaction and a paymentId' => ['answer' => ['success' => false, 'errorReason' => 'settlement_pending', 'transaction' => $tx, 'paymentId' => 'pay_1']],
    'refused, reason not a string' => ['answer' => ['success' => false, 'errorReason' => 5, 'transaction' => 7, 'paymentId' => 3]],
    'success as a string' => ['answer' => ['success' => 'true']],
    'facilitator down' => ['unavailable' => true],
    'facilitator broken' => ['throws' => true],
] as $name => $how) {
    $settle = function () use ($how) {
        if ($how['unavailable'] ?? false) {
            throw new FacilitatorException('down');
        }
        if ($how['throws'] ?? false) {
            throw new \RuntimeException('broken');
        }

        return $how['answer'];
    };
    $runCases[] = ['name' => $name] + $how + ['receipt' => Settlement::run($settle, [], $req84532)];
}
$verifyCases = [];
foreach ([
    'valid' => ['isValid' => true],
    'invalid with reason' => ['isValid' => false, 'invalidReason' => 'insufficient_funds'],
    'invalid without reason' => ['isValid' => false],
    'invalid with empty reason' => ['isValid' => false, 'invalidReason' => ''],
    'invalid with a non-string reason' => ['isValid' => false, 'invalidReason' => 5],
] as $name => $answer) {
    $f = new class($answer) implements Facilitator {
        public function __construct(private array $a)
        {
        }

        public function verify(array $payment, array $req): array
        {
            return $this->a;
        }

        public function settle(array $payment, array $req): array
        {
            return [];
        }
    };
    $verifyCases[] = ['name' => $name, 'answer' => $answer, 'reason' => (Settlement::verifier($f))([], $req84532)];
}
$a1 = ['scheme' => 'exact', 'network' => 'eip155:84532', 'asset' => '0xAAAA000000000000000000000000000000000001'];
$a2 = ['scheme' => 'exact', 'network' => 'eip155:84532', 'asset' => '0xBBBB000000000000000000000000000000000002'];
$s1 = ['scheme' => 'exact', 'network' => 'solana:devnet', 'asset' => 'MintAAA'];
$s2 = ['scheme' => 'exact', 'network' => 'solana:devnet', 'asset' => 'MintBBB'];
$offerCases = [];
foreach ([
    'one match' => [[$a1], $a1],
    'two on EVM, asset in another case' => [[$a1, $a2], ['asset' => strtolower($a2['asset'])] + $a2],
    'two on EVM, unknown asset: first' => [[$a1, $a2], ['asset' => '0xCCCC000000000000000000000000000000000003'] + $a1],
    'two on Solana, exact asset' => [[$s1, $s2], $s2],
    'two on Solana, asset in another case: first' => [[$s1, $s2], ['asset' => 'mintbbb'] + $s2],
    'no match' => [[$a1], ['network' => 'eip155:1'] + $a1],
    'accepted not an array' => [[$a1], 'x'],
    'accepted missing' => [[$a1], null],
    'asset not a string' => [[$a1, $a2], ['asset' => 5] + $a2],
] as $name => [$accepts, $accepted]) {
    $offerCases[] = ['name' => $name, 'accepts' => $accepts, 'accepted' => $accepted, 'offer' => Settlement::offer($accepts, $accepted)];
}
$keyCases = [];
foreach ([$base, $long, $noAuth] as $i => $p) {
    $keyCases[] = ['payment' => $p, 'key' => Settlement::key($p)];
}
write($out, 'settlement', ['settled' => $settledCases, 'run' => $runCases, 'verifier' => $verifyCases, 'offer' => $offerCases, 'key' => $keyCases, 'mock' => Settlement::mock()($base, $req)]);
