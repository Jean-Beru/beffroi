<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;

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

    public const string A_KEY_OF_THE_SUBSCRIPTION = 'a key of the subscription as the browser wrote it (RFC 8291 §3.1), which reaches no browser without the sealed endpoint it was drawn for';

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
            'beffroi_tenant' => [
                'slug' => new NoPersonalDatum(self::THE_TENANT),
                'issuer' => new NoPersonalDatum(self::THE_TENANT),
                'name' => new NoPersonalDatum(self::THE_TENANT),
                'authentication_context_policy' => new NoPersonalDatum('the authentication classes the tenant announces, which name predicates and no person'),
                'login_floor' =>
                    new NoPersonalDatum('the predicate every login of this tenant satisfies at the least (issue #327): one of the four names this provider defines, and nothing of anybody who signs in'),
                'look' => new NoPersonalDatum('the logo and the two colours a tenant gives its pages (issue #449), beside the name it is already named by: what every page hands to every visitor before anybody has signed in'),
                'self_served_claims' =>
                    new NoPersonalDatum('the names of the claims the people of this tenant may change of themselves (issue #452): names of claims, never a value and never a person'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            // Every act of the provider, written down (issue #454): four facts and two names, and no column
            // a caller fills with whatever it has.
            'beffroi_journal' => [
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'act' => new NoPersonalDatum('the name of the act, which an event gives itself and which names no person'),
                'occurred_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'context' => new Sealed('journal'),
                'subject' => new NoPersonalDatum(self::THE_SUBJECT),
                'client' => new NoPersonalDatum('the client the act concerned, by the identifier it was registered under'),
            ],
            // What a client was given of a person, at one act (issue #590). The three columns that say what
            // left are sealed, where a consent holds the same values in the clear: a consent is a
            // permission, one row per client, and this is one row per act, so a dump of this table is what
            // an application obtained of somebody day by day. That the obtaining happened is in the journal
            // above, in the clear, as the act of it.
            'beffroi_disclosure' => [
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'subject' => new NoPersonalDatum(self::THE_SUBJECT),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'act' => new NoPersonalDatum('the name of the act it left with, which an event gives itself and which names no person'),
                'handed_over_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'scopes' => new Sealed('disclosure'),
                'claims' => new Sealed('disclosure'),
                'authorization_details' => new Sealed('disclosure'),
                'token_shape' => new NoPersonalDatum('the shape the access token was written in, which names no person'),
            ],
            // Everything this provider holds about one person, in one file they asked for (issue #453). The
            // one column of this schema where everything the other families seal stands in clear at once,
            // which is why it is sealed like the rest and carries no exemption: a dump that read this one
            // would read all of it.
            'beffroi_personal_archive' => [
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'asked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'built_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'content' => new Sealed('personal_archive'),
            ],
            // What a claim of a person used to say, and what they made it say (issue #482): the two values
            // are that person's own, so they are sealed as the column they came from is, and the
            // provenance beside them as every provenance is.
            'beffroi_claim_change' => [
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'claim' => new NoPersonalDatum('the name of the claim that changed, which is a name of OIDC Core §5.1 and never a value'),
                'was' => new Sealed('claim_change'),
                'became' => new Sealed('claim_change'),
                'changed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'context' => new Sealed('claim_change'),
            ],
            'beffroi_user' => [
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
                'profile' => new Sealed('user'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'beffroi_linked_identity' => [
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
            'beffroi_passkey_credential' => [
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'name' => new Sealed('passkey_credential'),
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
            'beffroi_password_credential' => [
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'hash_changed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'breach_checked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'breach_found_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'hash' => new NoPersonalDatum(self::HASHED . ', with the algorithm it was computed with and the parameters it was computed under'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_totp_credential' => [
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
            'beffroi_push_subscription' => [
                'endpoint' => new Sealed('push_subscription'),
                'endpoint_hash' => new NoPersonalDatum(self::HASHED),
                'public_key' => new NoPersonalDatum(self::A_KEY_OF_THE_SUBSCRIPTION),
                'auth_secret' => new NoPersonalDatum(self::A_KEY_OF_THE_SUBSCRIPTION),
                'application_server_kid' => new NoPersonalDatum('names the key of the tenant a push to this browser is signed with'),
                'label' => new Sealed('push_subscription'),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_pushed_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_group' => [
                'name' => new NoPersonalDatum('names a group of the tenant, an organisational unit and not a person'),
                'source' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'created_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'beffroi_group_membership' => [
                'source' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'added_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'group_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_authentication_session' => [
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
            'beffroi_interaction' => [
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
                'login_hint' => new Sealed('interaction'),
                'ui_locales' => new NoPersonalDatum('the language a request asked the page to be served in, not a language the provider knows of the person'),
                'acr_values' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'display' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'id_token_hint' => new Sealed('interaction'),
                'claims' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'response_mode' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'dpop_jkt' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'consent_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_authorization_code' => [
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
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_pushed_authorization_request' => [
                'used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'parameters' => new Sealed('pushed_authorization_request'),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'carried_by_signed_object' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'request_uri_hash' => new NoPersonalDatum(self::HASHED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'beffroi_access_token' => [
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
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_subject_access_token' => [
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'resources' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'cnf' => new NoPersonalDatum('what a token is bound to, the thumbprint of a key or of a certificate (RFC 9449 §6, RFC 8705 §3)'),
                'issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'token_hash' => new NoPersonalDatum(self::HASHED),
                'sub' => new NoPersonalDatum(self::THE_SUBJECT),
                'person' => new NoPersonalDatum(self::THE_SUBJECT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'act' => new NoPersonalDatum('the actor a delegated token names, which is a client and never a person (RFC 8693 §4.1)'),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'beffroi_client_access_token' => [
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
            'beffroi_refresh_token_family' => [
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'granting_record_hash' => new NoPersonalDatum(self::HASHED),
                'grant_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'started_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
            ],
            'beffroi_refresh_token' => [
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

                'authentication' => new NoPersonalDatum(self::WHAT_THE_SESSION_PROVED),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'session_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_device_authorization_request' => [
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
            'beffroi_backchannel_authentication_request' => [
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
            'beffroi_consent' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'scopes' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'authorization_details' => new NoPersonalDatum(self::WHAT_THE_REQUEST_ASKED),
                'granted_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'revoked_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
                'user_id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
            ],
            'beffroi_client' => [
                'client_id' => new NoPersonalDatum(self::A_CLIENT),
                'metadata' => new Sealed('client'),
                'assigned_metadata' => new Sealed('client'),
                'registration_access_token' => new NoPersonalDatum(self::HASHED),
                'secret' => new Sealed('client'),
                'client_id_issued_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'last_used_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'client_secret_expires_at' => new NoPersonalDatum(self::NAMES_NO_PERSON),
                'id' => new NoPersonalDatum(self::DRAWN_AT_RANDOM),
                'tenant_id' => new NoPersonalDatum(self::THE_TENANT),
            ],
            'beffroi_initial_access_token' => [
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
            'beffroi_pairwise_subject' => [
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
            'beffroi_data_key' => [
                'id' => new NoPersonalDatum('the reference a sealed value carries, drawn as a UUIDv7 so that the newest key of a scope is the last row'),
                'scope' =>
                    new NoPersonalDatum('the slug of a tenant and the family of columns its key seals, which names an organisation and a set of columns'),
                'key_material' => new NoPersonalDatum(self::AN_ENVELOPE),
                'master_key_id' => new NoPersonalDatum('the key of the KMS that wrapped this row, written here so that a read resolves whatever wrote it'),
                'client' => new NoPersonalDatum('the name the configuration gives the KMS that wrapped this row, for the same reason'),
                'binding' =>
                    new NoPersonalDatum('a 32-byte proof, over the reference and the scope this row states and the key it holds, that the key was minted for them: a row copied under another reference or another scope is refused once its key is open, which is the parade of the bridge to a sealed value crossing a tenant'),
            ],
        ];
    }
}
