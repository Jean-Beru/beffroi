<?php

// The two people of the identity provider of the judge (issue #788), by "<username>:<password>" as the exampleauth
// module of SimpleSAMLphp reads them (authsources.php), and the attributes it asserts of each. Returned rather than
// assigned, so that the walk of "castor saml-idp" reads the same file to sign in as them and the two never disagree.
//
// Their passwords are fixtures of this laboratory identity provider, written here for anyone who reads the repository
// to see, as its salt is: they open nothing but this container, and never a password of the provider, whose
// development user is alice@op.localhost (castor provision), in another domain than these two.
//
// - alice, whom the provider has never seen: her first sign-in creates her, and her second creates nothing;
// - bob, in the group "beffroi-admins", the value the declaration of this identity provider maps to a group of the
//   tenant (issue #782).
//
// "uid" is what the persistent NameID of a person is drawn from (metadata/saml20-idp-hosted.php).
return [
    'alice:alice-at-the-lab-idp' => [
        'uid' => ['alice'],
        'mail' => ['alice@idp.example'],
        'givenName' => ['Alice'],
        'sn' => ['Liddell'],
    ],
    'bob:bob-at-the-lab-idp' => [
        'uid' => ['bob'],
        'mail' => ['bob@idp.example'],
        'givenName' => ['Bob'],
        'sn' => ['Builder'],
        'groups' => ['beffroi-admins'],
    ],
];
