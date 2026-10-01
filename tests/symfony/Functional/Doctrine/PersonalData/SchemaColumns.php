<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use Heidi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;

/**
 * Every column of every table of the two pure-PHP packages, and what it is: a column a dump gives away
 * with the reason that gives nothing away, a column sealed under the data key of its tenant, or a
 * personal datum this spike seals with the issue that owes it.
 *
 * Decision 0011 asks for the test this list feeds: "Toute colonne à venir qui porte une donnée
 * personnelle, par construction : un test énumère les colonnes du schéma et refuse une colonne qui
 * n'est ni déclarée hors données personnelles, ni d'un type chiffré." Written after the columns are
 * sealed the list says what was done; written before them it says what there is to do, and this is
 * the list the spike works from.
 *
 * Three rules hold it together.
 *
 * A column is named here once, whichever list it belongs to, so that no column can be in two and none
 * can be read from a name: the walk (ClassifiedSchema) holds this against the schema Doctrine builds
 * and reports a column named in neither, a line whose column has gone, and a line the schema has
 * outgrown.
 *
 * A reason is a sentence, because a person reads it: the sentences several columns share are the
 * constants below, the four categories of decision 0011 among them, and a column whose reason no
 * category says as well carries one of its own.
 *
 * An owed line carries its issue, on the model of the "known" list of CONFORMANCE_PLANS: the day the
 * column is found sealed the walk fails, so the line is deleted rather than carried.
 */
final readonly class SchemaColumns
{
    public const string HASHED = 'a digest does not open: the column holds the fingerprint of what was presented and never the value';

    public const string DRAWN_AT_RANDOM = 'drawn at random, and designates nobody without the table that joins it';

    public const string PUBLIC_BY_CONSTRUCTION = 'public by construction: what the browser, the authenticator or the client publishes already';

    public const string NAMES_NO_PERSON = 'names no person: a date, a state, or a count of what the provider did';

    public const string THE_TENANT = 'designates an organisation and not a person';

    public const string THE_SUBJECT = 'a stable pseudonym every token carries in the clear and every table joins on';

    public const string A_CLIENT = 'names a client application, and never a person';

    public const string WHAT_THE_REQUEST_ASKED = 'what a request asked of the protocol, not what the provider knows of the person';

    public const string WHAT_THE_SESSION_PROVED = 'what the session proved, which every token issued from it carries in the clear (OIDC Core §2)';

    public const string AN_ENVELOPE = 'the envelope the KMS of the tenant sealed, and nothing else';

    public const string A_BLIND_INDEX = 'a keyed tag of a sealed value, under the index key of its tenant: it says which rows share a value and never what that value is (decision 0011)';

    /**
     * The Doctrine types of the bundle that seal what they store, by the name a mapping gives them, read
     * from the declaration of the bundle and not kept here: a second list would be a second thing to be
     * wrong, and what a column seals under is what its mapping names.
     *
     * The walk refuses a column declared sealed that carries none of them, and a column that carries one
     * whose line still owes it, so the declaration and the mappings cannot drift apart.
     *
     * @return list<string>
     */
    public static function sealingTypes(): array
    {
        return EncryptedColumnTypes::names();
    }

    /**
     * @return array<string, array<string, ColumnClassificationInterface>> table, then column
     */
    public static function all(): array
    {
        return [
            'heidi_tenant' => [
                'slug' => new NoPersonalDatum(self::THE_TENANT),
                'issuer' => new NoPersonalDatum(self::THE_TENANT),
                'name' => new NoPersonalDatum(self::THE_TENANT),
                'authentication_context_policy' => new NoPersonalDatum('the authentication classes the tenant announces, which name predicates and no person'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_user' => [
                'subject' => new NoPersonalDatum(self::THE_SUBJECT),
                'username' => new Sealed('user'),
                'username_index' => new NoPersonalDatum(self::A_BLIND_INDEX),
                'email' => new Sealed('user'),
                'email_index' => new NoPersonalDatum(self::A_BLIND_INDEX),
                'email_verified' => new NoPersonalDatum('whether an address or a number was verified, which says nothing of either'),
                'phone_number' => new Sealed('user'),
                'phone_number_verified' => new NoPersonalDatum('whether an address or a number was verified, which says nothing of either'),
                'address' => new Sealed('user'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'updated_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'disabled_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'name' => new Sealed('user'),
                'given_name' => new Sealed('user'),
                'family_name' => new Sealed('user'),
                'middle_name' => new Sealed('user'),
                'nickname' => new Sealed('user'),
                'preferred_username' => new Sealed('user'),
                'profile_url' => new Sealed('user'),
                'picture_url' => new Sealed('user'),
                'website_url' => new Sealed('user'),
                'gender' => new Sealed('user'),
                'birthdate' => new Sealed('user'),
                'zoneinfo' => new Sealed('user'),
                'locale' => new Sealed('user'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_linked_identity' => [
                'provider' => new Sealed('linked_identity'),
                'provider_index' => new NoPersonalDatum(self::A_BLIND_INDEX),
                'subject' => new Sealed('linked_identity'),
                'subject_index' => new NoPersonalDatum(self::A_BLIND_INDEX),
                'claims' => new Sealed('linked_identity'),
                'linked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_seen_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_passkey_credential' => [
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'name' => new Owed('heidi#405', 'the name a person gave a passkey, so as to tell theirs apart'),
                'credential_id' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'public_key' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'sign_count' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'transports' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'backup_eligible' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'backed_up' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'aaguid' => new NoPersonalDatum(self::PUBLIC_BY_CONSTRUCTION),
                'user_handle' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_password_credential' => [
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'hash_changed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'hash_algorithm' => new NoPersonalDatum('the algorithm a digest was computed with, and the parameters it was computed under'),
                'hash_encoded' => new NoPersonalDatum(self::HASHED),
                'hash_parameters' => new NoPersonalDatum('the algorithm a digest was computed with, and the parameters it was computed under'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_totp_credential' => [
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'sealed_secret' => new NoPersonalDatum(self::AN_ENVELOPE),
                'last_accepted_step' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'backup_codes' => new NoPersonalDatum(self::HASHED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_push_subscription' => [
                'endpoint' => new Owed('heidi#405', 'a URL that designates one browser on one device'),
                'endpoint_hash' => new NoPersonalDatum(self::HASHED),
                'public_key' =>
                    new NoPersonalDatum('a key of the subscription as the browser wrote it (RFC 8291 §3.1), which reaches no browser without the endpoint issue #405 seals'),
                'auth_secret' =>
                    new NoPersonalDatum('a key of the subscription as the browser wrote it (RFC 8291 §3.1), which reaches no browser without the endpoint issue #405 seals'),
                'application_server_kid' => new NoPersonalDatum('names the key of the tenant a push to this browser is signed with'),
                'label' => new Owed('heidi#405', 'the label a person typed for one of their devices'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_pushed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_group' => [
                'name' => new NoPersonalDatum('names a group of the tenant, an organisational unit and not a person'),
                'source' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_group_membership' => [
                'source' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'added_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'group_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_authentication_session' => [
                'established_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'proofs' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'last_seen_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'ended_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'ended_by' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'created_from' => new Sealed('authentication_session'),
                'last_seen_from' => new Sealed('authentication_session'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_interaction' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'locale' => new NoPersonalDatum('the language a request asked the page to be served in, not a language the provider knows of the person'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'completed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'request_uri_hash' => new NoPersonalDatum(self::HASHED),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'redirect_uri' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'code_challenge' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'state' => new NoPersonalDatum('an opaque value the client drew to tie its own request to the answer it gets back'),
                'nonce' => new NoPersonalDatum('an opaque value the client drew to tie its own request to the answer it gets back'),
                'prompts' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'max_age' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'login_hint' => new Owed('heidi#406', 'a username, an electronic address, or a "sub" this provider wrote (OIDC Core §3.1.2.1)'),
                'ui_locales' => new NoPersonalDatum('the language a request asked the page to be served in, not a language the provider knows of the person'),
                'acr_values' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'display' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'id_token_hint' => new Owed('heidi#406', 'an ID token this provider issued, which names the person it was issued for'),
                'claims' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'response_mode' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'dpop_jkt' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'consent_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_authorization_code' => [
                'used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'redirect_uri' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'nonce' => new NoPersonalDatum('an opaque value the client drew to tie its own request to the answer it gets back'),
                'code_challenge' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'dpop_jkt' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'claims' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'code_hash' => new NoPersonalDatum(self::HASHED),
                'authenticated_at' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'amr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'acr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_pushed_authorization_request' => [
                'used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'parameters' => new Owed(
                    'heidi#406',
                    'the parameters of a pushed request as the client wrote them, "login_hint" and "id_token_hint" among them (RFC 9126 §2.2)',
                ),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'carried_by_signed_object' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'request_uri_hash' => new NoPersonalDatum(self::HASHED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_access_token' => [
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'cnf' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'token_hash' => new NoPersonalDatum(self::HASHED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'claims' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authenticated_at' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'amr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'acr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_subject_access_token' => [
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'cnf' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'token_hash' => new NoPersonalDatum(self::HASHED),
                'sub' => new NoPersonalDatum(self::THE_SUBJECT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'act' => new NoPersonalDatum('the actor a delegated token names, which is a client and never a person (RFC 8693 §4.1)'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_client_access_token' => [
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'cnf' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'token_hash' => new NoPersonalDatum(self::HASHED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_refresh_token' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'claims' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'rotated_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'cnf' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'token_hash' => new NoPersonalDatum(self::HASHED),
                'family_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'family_granting_record_hash' => new NoPersonalDatum(self::HASHED),
                'family_grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'family_started_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'family_expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'authenticated_at' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'amr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'acr' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_device_authorization_request' => [
                'used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'user_code_hash' => new NoPersonalDatum(self::HASHED),
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'poll_interval' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_polled_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'approved_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'denied_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'device_code_hash' => new NoPersonalDatum(self::HASHED),
                'requested_from' => new Sealed('device_authorization_request'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_backchannel_authentication_request' => [
                'used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'binding_message' => new Sealed('backchannel_authentication_request'),
                'acr_values' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'sealed_auth_request_id' => new NoPersonalDatum(self::AN_ENVELOPE),
                'sealed_notification_token' => new NoPersonalDatum(self::AN_ENVELOPE),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'poll_interval' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_polled_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'approved_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'denied_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'auth_request_id_hash' => new NoPersonalDatum(self::HASHED),
                'requested_from' => new Sealed('backchannel_authentication_request'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_consent' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'granted_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'heidi_client' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'metadata' => new Owed(
                    'heidi#407',
                    'the metadata a client registered, the "contacts" of RFC 7591 §2 among them, which are the electronic addresses of people',
                ),
                'assigned_metadata' => new Owed('heidi#407', 'what the provider assigned a registration, read back beside what the client said of itself'),
                'registration_access_token' => new NoPersonalDatum(self::HASHED),
                'secret' => new Owed('heidi#407', 'a digest for a method that receives a secret, and a shared secret in the clear for "client_secret_jwt"'),
                'client_id_issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'client_secret_expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_initial_access_token' => [
                'digest' => new NoPersonalDatum(self::HASHED),
                'name' => new NoPersonalDatum('the name an operator gave a token, so that one can be told from another'),
                'registrations_allowed' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'registrations_served' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'heidi_pairwise_subject' => [
                'sector' => new NoPersonalDatum('the sector a client registered, a host or the URL of a document, not a person'),
                'subject' => new NoPersonalDatum(self::THE_SUBJECT),
                'assigned_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            // The one table here no mapping of the bundle describes: the store of the data keys puts it in
            // the schema the ORM assembles, through the listener of its ORM bridge (decisions 0011 and
            // 0018). It is where every sealed column of this schema takes its key from, and it holds no
            // personal datum of its own: a dump of it alone opens nothing, the master key never being in it.
            'heidi_data_key' => [
                'id' => new NoPersonalDatum('the reference a sealed value carries, drawn as a UUIDv7 so that the newest key of a scope is the last row'),
                'scope' =>
                    new NoPersonalDatum('the slug of a tenant and the family of columns its key seals, which names an organisation and a set of columns'),
                'key_material' => new NoPersonalDatum(self::AN_ENVELOPE),
                'master_key_id' => new NoPersonalDatum('the key of the KMS that wrapped this row, written here so that a read resolves whatever wrote it'),
                'client' => new NoPersonalDatum('the name the configuration gives the KMS that wrapped this row, for the same reason'),
            ],
        ];
    }
}
