<?php

declare(strict_types=1);

/*
 * HttpFacilitator against scripted HTTP answers: what PHP sends (method, path, auth, body) and what it
 * makes of each answer (the array it returns, or a FacilitatorException). Written to vectors/facilitator.json.
 * Run by export.sh.
 */

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Quebracho\X402\Authorization;
use Quebracho\X402\FacilitatorException;
use Quebracho\X402\HttpFacilitator;
use Quebracho\X402\Networks;
use Quebracho\X402\Signer;

[$self, $lib, $out] = $argv + [null, null, null];
require $lib.'/vendor/autoload.php';

final class TransportDown extends \RuntimeException implements ClientExceptionInterface
{
}

/** Answers from a script, in order, and records what was sent. */
final class ScriptedClient implements ClientInterface
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
            'authorization' => $request->getHeaderLine('Authorization') ?: null,
            'content_type' => $request->getHeaderLine('Content-Type') ?: null,
            'body' => '' === $body ? null : json_decode($body, true),
        ];
        $a = array_shift($this->answers) ?? ['down' => true];
        if ($a['down'] ?? false) {
            throw new TransportDown('connection refused');
        }

        return new Response($a['status'], ['Content-Type' => 'application/json'], $a['body']);
    }
}

$req = Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD');
$buyer = new Signer('0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
$payment = Authorization::pay($buyer, ['x402Version' => 2, 'resource' => ['url' => 'https://device.test/r'], 'accepts' => [$req]], $req, 1_800_000_000, '0x'.str_repeat('0', 63).'1');
$from = $buyer->address();
$tx = '0x'.str_repeat('ab', 32);
$j = fn (array $a) => json_encode($a);
$ok = fn (array $extra = []) => ['status' => 200, 'body' => $j($extra + ['success' => true, 'transaction' => $tx, 'network' => 'eip155:84532', 'payer' => $from])];
$pending = ['status' => 202, 'body' => $j(['success' => false, 'errorReason' => 'settlement_pending', 'extensions' => ['settlement-status' => ['paymentId' => 'pay_123']]])];

$cases = [
    ['verify', 'valid', [['status' => 200, 'body' => '{"isValid":true}']]],
    ['verify', 'refused with a reason', [['status' => 200, 'body' => '{"isValid":false,"invalidReason":"insufficient_funds"}']]],
    ['verify', 'refused with a 4xx', [['status' => 400, 'body' => '{"isValid":false,"invalidReason":"invalid_signature"}']]],
    ['verify', 'server error', [['status' => 500, 'body' => '{"message":"boom"}']]],
    ['verify', 'not json', [['status' => 200, 'body' => 'hello']]],
    ['verify', 'not an x402 answer', [['status' => 200, 'body' => '{"ok":1}']]],
    ['verify', 'isValid as a string', [['status' => 200, 'body' => '{"isValid":"true"}']]],
    ['verify', 'transport down', [['down' => true]]],
    ['settle', 'consistent', [$ok()]],
    ['settle', 'payer in another case', [$ok(['payer' => strtolower($from)])]],
    ['settle', 'no payer named', [['status' => 200, 'body' => $j(['success' => true, 'transaction' => $tx, 'network' => 'eip155:84532'])]]],
    ['settle', 'another payer', [$ok(['payer' => '0x0000000000000000000000000000000000000001'])]],
    ['settle', 'another network', [$ok(['network' => 'eip155:8453'])]],
    ['settle', 'transaction not bytes32', [$ok(['transaction' => '0xabc'])]],
    ['settle', 'no transaction', [['status' => 200, 'body' => $j(['success' => true, 'network' => 'eip155:84532', 'payer' => $from])]]],
    ['settle', 'success as a string', [$ok(['success' => 'true'])]],
    ['settle', 'refused with a 402', [['status' => 402, 'body' => '{"success":false,"errorReason":"insufficient_funds","transaction":""}']]],
    ['settle', 'server error with an x402 reason', [['status' => 503, 'body' => '{"errors":[{"reason":"rpc_down"}]}']]],
    ['settle', 'transport down', [['down' => true]]],
    ['settle', 'pending, then completed at /status', [$pending, ['status' => 200, 'body' => $j(['status' => 'completed', 'transaction' => $tx, 'network' => 'eip155:84532', 'payer' => $from])]]],
    ['settle', 'pending, then failed at /status', [$pending, ['status' => 200, 'body' => '{"status":"failed","reason":"insufficient_funds"}']]],
    ['settle', 'pending through every poll', [$pending, ['status' => 200, 'body' => '{"status":"pending"}'], ['status' => 200, 'body' => '{"status":"pending"}'], ['status' => 200, 'body' => '{"status":"pending"}']]],
    ['settle', 'pending, /status unreachable', [$pending, ['down' => true]]],
    ['settle', 'pending with a paymentId not safe in a URL', [['status' => 202, 'body' => $j(['success' => false, 'errorReason' => 'settlement_pending', 'extensions' => ['settlement-status' => ['paymentId' => '../../admin']]])]]],
    ['supported', 'kinds', [['status' => 200, 'body' => '{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"}]}']]],
    ['supported', 'no kinds', [['status' => 200, 'body' => '{"other":1}']]],
];

$f = new Psr17Factory();
$result = [];
foreach ($cases as [$op, $name, $answers]) {
    foreach ([null, 'secret-key'] as $bearer) {
        $client = new ScriptedClient($answers);
        $facilitator = new HttpFacilitator($client, $f, $f, 'https://facilitator.test/x402/', $bearer, pollDelaySeconds: 0, pollAttempts: 3);
        try {
            $answer = match ($op) {
                'verify' => $facilitator->verify($payment, $req),
                'settle' => $facilitator->settle($payment, $req),
                'supported' => $facilitator->supported(),
            };
            $outcome = ['answer' => $answer];
        } catch (FacilitatorException) {
            $outcome = ['unavailable' => true];
        }
        $result[] = ['op' => $op, 'name' => $name, 'bearer' => $bearer, 'payment' => $payment, 'req' => $req, 'answers' => $answers, 'sent' => $client->sent] + $outcome;
    }
}

$commit = (string) getenv('X402_COMMIT');
file_put_contents("$out/facilitator.json", json_encode(['source' => 'quebracho/x402'.('' !== $commit ? " @ $commit" : ''), 'generator' => 'conformance/facilitator.php', 'cases' => $result], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR)."\n");
echo 'facilitator.json: '.count($result)." cases\n";
