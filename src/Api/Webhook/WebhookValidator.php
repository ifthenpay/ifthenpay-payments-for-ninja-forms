<?php

declare(strict_types=1);

namespace Ifthenpay\NinjaForms\Api\Webhook;

use Ifthenpay\NinjaForms\NinjaForms\SubmissionStore;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Anti-phishing + amount validation for an inbound webhook payload, checked
 * against the pending payment record it claims to resolve.
 */
class WebhookValidator
{
    private const AMOUNT_TOLERANCE = 0.01;

    /**
     * @param array<string, mixed> $record As stored by SubmissionStore.
     */
    public function is_valid(WebhookPayload $payload, array $record): bool
    {
        if (! $this->has_valid_key($payload, $record)) {
            return false;
        }

        return abs($payload->amount() - (float) $record['amount']) <= self::AMOUNT_TOLERANCE;
    }

    /**
     * Failure notices carry no amount, so this is all they get checked
     * against — without it anyone could cancel a pending ref by guessing it.
     *
     * @param array<string, mixed> $record As stored by SubmissionStore.
     */
    public function has_valid_key(WebhookPayload $payload, array $record): bool
    {
        $stored_key = (string) ($record['gateway_key'] ?? '');

        if ('' === $stored_key || SubmissionStore::MANUAL_GATEWAY_KEY === $stored_key) {
            return false;
        }

        // An un-urlencoded '+' in the base64 arrives as a space.
        $gateway_key = (string) base64_decode(str_replace(' ', '+', $payload->apk()), true);

        return '' !== $gateway_key && hash_equals($stored_key, $gateway_key);
    }
}
