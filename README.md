NI# BITCOIN-BROWSER
https://github.com/afortunado21/BITCOIN-BROWSER.wiki.git
New coin with the genesis of Bitcoin

* (16 Apr 2013) Added private derivation for i ≥ 0x80000000 (less risk of parent private key leakage)
* (30 Apr 2013) Switched from multiplication by I<sub>L</sub> to addition of I<sub>L</sub> (faster, easier implementation)
* (25 May 2013) Added test vectors
* (15 Jan 2014) Rename keys with index ≥ 0x80000000 to hardened keys, and add explicit conversion functions.
* (24 Feb 2017) Added test vectors for hardened derivation with leading zeros

<pre>
  BIP: 32
  Layer: Applications
  Comments-Summary: No comments yet.
  Comments-URI:https://github.com/afortunado21/BITCOIN-BROWSER.wiki.git comment :BIP-0032
  Status: Finalbitcoin
  Type: Informational
  Created: 2019-23-11
  License: 2-clause BSD
</pre>

==Abstract==

 ("HD Wallets"): wallets which can be shared partially or entirely with different systems, each with or without the ability to spend coins.

The specification is intended to set a standard for deterministic wallets that can be interchanged between different clients. Although the wallets described here have many features, not all are required by supporting clients.

The specification consists of two parts. In a first part, a system for deriving a tree of keypairs from a single seed is presented. The second part demonstrates how to build a wallet structure on top of such a tree.

==Copyright==

This BIP is licensed under the 2-clause BSD license.

==Motivation==

The Bitcoin reference client uses randomly generated keys. In order to avoid the necessity for a backup after every transaction, (by default) 100 keys are cached in a pool of reserve keys. Still, these wallets are not intended to be shared and used on several systems simultaneously. They support hiding their private keys by using the wallet encrypt feature and not sharing the password, but such "neutered" wallets lose the power to generate public keys as well.

Deterministic wallets do not require such frequent backups, and elliptic curve mathematics permit schemes where one can calculate the public keys without revealing the private keys. This permits for example a webshop business to let its webserver generate fresh addresses (public key hashes) for each order or for each customer, without giving the webserver access to the corresponding private keys (which are required for spending the received funds).

However, deterministic wallets typically consist of a single "chain" of keypairs. The fact that there is only one chain means that sharing a wallet happens on an all-or-nothing basis. However, in some cases one only wants some (public) keys to be shared and recoverable. In the example of a webshop, the webserver does not need access to all public keys of the merchant's wallet; only to those addresses which are used to receive customer's payments, and not for example the change addresses that are generated when the merchant spends money. Hierarchical deterministic wallets allow such selective sharing by supporting multiple keypair chains, derived from a single root.

==Specification: Key derivation==

===Conventions===

In the rest of this text we will assume the public key cryptography used in Bitcoin, namely elliptic curve cryptography using the field and curve parameters defined by secp256k1 (http://www.secg.org/sec2-v2.pdf). Variables below are either:
* Integers modulo the order of the curve (referred to as n).
* Coordinates of points on the curve.
* Byte sequences.

Addition (+) of two coordinate pair is defined as application of the EC group operation.
Concatenation (||) is the operation of appending one byte sequence onto another.

As standard conversion functions, we assume:
* point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
* ser<sub>32</sub>(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
* ser<sub>256</sub>(p): serializes the integer p as a 32-byte sequence, most significant byte first.
* ser<sub>P</sub>(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser<sub>256</sub>(x), where the header byte depends on the parity of the omitted y coordinate.
* parse<sub>256</sub>(p): interprets a 32-byte sequence as a 256-bit number, most significant byte first.


===Extended keys===

In what follows, we will define a function that derives a number of child keys from a parent key. In order to prevent these from depending solely on the key itself, we extend both private and public keys first with an extra 256 bits of entropy. This extension, called the chain code, is identical for corresponding private and public keys, and consists of 32 bytes.

We represent an extended private key as (k, c), with k the normal private key, and c the chain code. An extended public key is represented as (K, c), with K = point(k) and c the chain code.

Each extended key has 2<sup>31</sup> normal child keys, and 2<sup>31</sup> hardened child keys. Each of these child keys has an index. The normal child keys use indices 0 through 2<sup>31</sup>-1. The hardened child keys use indices 2<sup>31</sup> through 2<sup>32</sup>-1. To ease notation for hardened key indices, a number i<sub>H</sub> represents i+2<sup>31</sup>.

===Child key derivation (CKD) functions===

Given a parent extended key and an index i, it is possible to compute the corresponding child extended key. The algorithm to do so depends on whether the child is a hardened key or not (or, equivalently, whether i ≥ 2<sup>31</sup>), and whether we're talking about private or public keys.

====Private parent key &rarr; private child key====

The function CKDpriv((k<sub>par</sub>, c<sub>par</sub>), i) &rarr; (k<sub>i</sub>, c<sub>i</sub>) computes a child extended private key from the parent extended private key:
* Check whether i ≥ 2<sup>31</sup> (whether the child is a hardened key).
** If so (hardened child): let I = HMAC-SHA512(Key = c<sub>par</sub>, Data = 0x00 || ser<sub>256</sub>(k<sub>par</sub>) || ser<sub>32</sub>(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
** If not (normal child): let I = HMAC-SHA512(Key = c<sub>par</sub>, Data = ser<sub>P</sub>(point(k<sub>par</sub>)) || ser<sub>32</sub>(i)).
* Split I into two 32-byte sequences, I<sub>L</sub> and I<sub>R</sub>.
* The returned child key k<sub>i</sub> is parse<sub>256</sub>(I<sub>L</sub>) + k<sub>par</sub> (mod n).
* The returned chain code c<sub>i</sub> is I<sub>R</sub>.
* In case parse<sub>256</sub>(I<sub>L</sub>) ≥ n or k<sub>i</sub> = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2<sup>127</sup>.)

The HMAC-SHA512 function is specified in [http://tools.ietf.org/html/rfc4231 RFC 4231].

====Public parent key &rarr; public child key====

The function CKDpub((K<sub>par</sub>, c<sub>par</sub>), i) &rarr; (K<sub>i</sub>, c<sub>i</sub>) computes a child extended public key from the parent extended public key. It is only defined for non-hardened child keys.
* Check whether i ≥ 2<sup>31</sup> (whether the child is a hardened key).
** If so (hardened child): return failure
** If not (normal child): let I = HMAC-SHA512(Key = c<sub>par</sub>, Data = ser<sub>P</sub>(K<sub>par</sub>) || ser<sub>32</sub>(i)).
* Split I into two 32-byte sequences, I<sub>L</sub> and I<sub>R</sub>.
* The returned child key K<sub>i</sub> is point(parse<sub>256</sub>(I<sub>L</sub>)) + K<sub>par</sub>.
* The returned chain code c<sub>i</sub> is I<sub>R</sub>.
* In case parse<sub>256</sub>(I<sub>L</sub>) ≥ n or K<sub>i</sub> is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.

====Private parent key &rarr; public child key====

The function N((k, c)) &rarr; (K, c) computes the extended public key corresponding to an extended private key (the "neutered" version, as it removes the ability to sign transactions).
* The returned key K is point(k).
* The returned chain code c is just the passed chain code.

To compute the public child key of a parent private key:
* N(CKDpriv((k<sub>par</sub>, c<sub>par</sub>), i)) (works always).
* CKDpub(N(k<sub>par</sub>, c<sub>par</sub>), i) (works only for non-hardened child keys).
The fact that they are equivalent is what makes non-hardened keys useful (one can derive child public keys of a given parent key without knowing any private key), and also what distinguishes them from hardened keys. The reason for not always using non-hardened keys (which are more useful) is security; see further for more information.

====Public parent key &rarr; private child key====

This is not possible.

===The key tree===

The next step is cascading several CKD constructions to build a tree. We start with one root, the master extended key m. By evaluating CKDpriv(m,i) for several values of i, we get a number of level-1 derived nodes. As each of these is again an extended key, CKDpriv can be applied to those as well.

To shorten notation, we will write CKDpriv(CKDpriv(CKDpriv(m,3<sub>H</sub>),2),5) as m/3<sub>H</sub>/2/5. Equivalently for public keys, we write CKDpub(CKDpub(CKDpub(M,3),2),5) as M/3/2/5. This results in the following identities:
* N(m/a/b/c) = N(m/a/b)/c = N(m/a)/b/c = N(m)/a/b/c = M/a/b/c.
* N(m/a<sub>H</sub>/b/c) = N(m/a<sub>H</sub>/b)/c = N(m/a<sub>H</sub>)/b/c.
However, N(m/a<sub>H</sub>) cannot be rewritten as N(m)/a<sub>H</sub>, as the latter is not possible.

Each leaf node in the tree corresponds to an actual key, while the internal nodes correspond to the collections of keys that descend from them. The chain codes of the leaf nodes are ignored, and only their embedded private or public key is relevant. Because of this construction, knowing an extended private key allows reconstruction of all descendant private keys and public keys, and knowing an extended public keys allows reconstruction of all descendant non-hardened public keys.

===Key identifiers===

Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256) of the serialized ECDSA public key K, ignoring the chain code. This corresponds exactly to the data used in traditional Bitcoin addresses. It is not advised to represent this data in base58 format though, as it may be interpreted as an address that way (and wallet software is not required to accept payment to the chain key itself).

The first 32 bits of the identifier are called the key fingerprint.

===Serialization format===

Extended public and private keys are serialized as follows:
* 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
* 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
* 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
* 4 bytes: child number. This is ser<sub>32</sub>(i) for i in x<sub>i</sub> = x<sub>par</sub>/i, with x<sub>i</sub> the key being serialized. (0x00000000 if master key)
* 32 bytes: the chain code
* 33 bytes: the public key or private key data (ser<sub>P</sub>(K) for public keys, 0x00 || ser<sub>256</sub>(k) for private keys)

This 78 byte structure can be encoded like other Bitcoin data in Base58, by first adding 32 checksum bits (derived from the double SHA-256 checksum), and then converting to the Base58 representation. This results in a Base58-encoded string of up to 112 characters. Because of the choice of the version bytes, the Base58 representation will start with "xprv" or "xpub" on mainnet, "tprv" or "tpub" on testnet.

Note that the fingerprint of the parent only serves as a fast way to detect parent and child nodes in software, and software must be willing to deal with collisions. Internally, the full 160-bit identifier could be used.

When importing a serialized extended public key, implementations must verify whether the X coordinate in the public key data corresponds to a point on the curve. If not, the extended public key is invalid.

===Master key generation===

The total number of possible extended keypairs is almost 2<sup>512</sup>, but the produced keys are only 256 bits long, and offer about half of that in terms of security. Therefore, master keys are not generated directly, but instead from a potentially short seed value.

* Generate a seed byte sequence S of a chosen length (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
* Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
* Split I into two 32-byte sequences, I<sub>L</sub> and I<sub>R</sub>.
* Use parse<sub>256</sub>(I<sub>L</sub>) as master secret key, and I<sub>R</sub> as master chain code.
In case I<sub>L</sub> is 0 or ≥n, the master key is invalid.

<img src=bip-0032/derivation.png></img>

==Specification: Wallet structure==

The previous sections specified key trees and their nodes. The next step is imposing a wallet structure on this tree. The layout defined in this section is a default only, though clients are encouraged to mimic it for compatibility, even if not all features are supported.

===The default wallet layout===

An HDW is organized as several 'accounts'. Accounts are numbered, the default account ("") being number 0. Clients are not required to support more than one account - if not, they only use the default account.

Each account is composed of two keypair chains: an internal and an external one. The external keychain is used to generate new public addresses, while the internal keychain is used for all other operations (change addresses, generation addresses, ..., anything that doesn't need to be communicated). Clients that do not support separate keychains for these should use the external one for everything.
* m/i<sub>H</sub>/0/k corresponds to the k'th keypair of the external chain of account number i of the HDW derived from master m.
* m/i<sub>H</sub>/1/k corresponds to the k'th keypair of the internal chain of account number i of the HDW derived from master m.

===Use cases===

====Full wallet sharing: m====

In cases where two systems need to access a single shared wallet, and both need to be able to perform spendings, one needs to share the master private extended key. Nodes can keep a pool of N look-ahead keys cached for external chains, to watch for incoming payments. The look-ahead for internal chains can be very small, as no gaps are to be expected here. An extra look-ahead could be active for the first unused account's chains - triggering the creation of a new account when used. Note that the name of the account will still need to be entered manually and cannot be synchronized via the block chain.

====Audits: N(m/*)====

In case an auditor needs full access to the list of incoming and outgoing payments, one can share all account public extended keys. This will allow the auditor to see all transactions from and to the wallet, in all accounts, but not a single secret key.

====Per-office balances: m/i<sub>H</sub>====

When a business has several independent offices, they can all use wallets derived from a single master. This will allow the headquarters to maintain a super-wallet that sees all incoming and outgoing transactions of all offices, and even permit moving money between the offices.

====Recurrent business-to-business transactions: N(m/i<sub>H</sub>/0)====

In case two business partners often transfer money, one can use the extended public key for the external chain of a specific account (M/i h/0) as a sort of "super address", allowing frequent transactions that cannot (easily) be associated, but without needing to request a new address for each payment.
Such a mechanism could also be used by mining pool operators as variable payout address.

====Unsecure money receiver: N(m/i<sub>H</sub>/0)====

When an unsecure webserver is used to run an e-commerce site, it needs to know public addresses that are used to receive payments. The webserver only needs to know the public extended key of the external chain of a single account. This means someone illegally obtaining access to the webserver can at most see all incoming payments but will not be able to steal the money, will not (trivially) be able to distinguish outgoing transactions, nor be able to see payments received by other webservers if there are several.

==Compatibility==

To comply with this standard, a client must at least be able to import an extended public or private key, to give access to its direct descendants as wallet keys. The wallet structure (master/account/chain/subchain) presented in the second part of the specification is advisory only, but is suggested as a minimal structure for easy compatibility - even when no separate accounts or distinction between internal and external chains is made. However, implementations may deviate from it for specific needs; more complex applications may call for a more complex tree structure.

==Security==

In addition to the expectations from the EC public-key cryptography itself:
* Given a public key K, an attacker cannot find the corresponding private key more efficiently than by solving the EC discrete logarithm problem (assumed to require 2<sup>128</sup> group operations).
the intended security properties of this standard are:
* Given a child extended private key (k<sub>i</sub>,c<sub>i</sub>) and the integer i, an attacker cannot find the parent private key k<sub>par</sub> more efficiently than a 2<sup>256</sup> brute force of HMAC-SHA512.
* Given any number (2 ≤ N ≤ 2<sup>32</sup>-1) of (index, extended private key) tuples (i<sub>j</sub>,(k<sub>i<sub>j</sub></sub>,c<sub>i<sub>j</sub></sub>)), with distinct i<sub>j</sub>'s, determining whether they are derived from a common parent extended private key (i.e., whether there exists a (k<sub>par</sub>,c<sub>par</sub>) such that for each j in (0..N-1) CKDpriv((k<sub>par</sub>,c<sub>par</sub>),i<sub>j</sub>)=(k<sub>i<sub>j</sub></sub>,c<sub>i<sub>j</sub></sub>)), cannot be done more efficiently than a 2<sup>256</sup> brute force of HMAC-SHA512.
Note however that the following properties does not exist:
* Given a parent extended public key (K<sub>par</sub>,c<sub>par</sub>) and a child public key (K<sub>i</sub>), it is hard to find i.
* Given a parent extended public key (K<sub>par</sub>,c<sub>par</sub>) and a non-hardened child private key (k<sub>i</sub>), it is hard to find k<sub>par</sub>.

===Implications===

Private and public keys must be kept safe as usual. Leaking a private key means access to coins - leaking a public key can mean loss of privacy.

Somewhat more care must be taken regarding extended keys, as these correspond to an entire (sub)tree of keys.

One weakness that may not be immediately obvious, is that knowledge of a parent extended public key plus any non-hardened private key descending from it is equivalent to knowing the parent extended private key (and thus every private and public key descending from it). This means that extended public keys must be treated more carefully than regular public keys.
It is also the reason for the existence of hardened keys, and why they are used for the account level in the tree. This way, a leak of account-specific (or below) private key never risks compromising the master or other accounts.


==Test Vectors==

===Test vector 1===

Seed (hex): 000102030405060708090a0b0c0d0e0f
* Chain m
** ext pub: bc1q87rwjxtg9rkenz74gvg4vmqr96j8y0ffpmzw59
** ext prv: bc1qakutpftvk7uatfraksknfncgmz0yc3yhyu6vzc
* Chain m/0<sub>H</sub>
** ext pub: bc1qxwetzw4d0jw3jz8nn7mh27t0zer9l2tkj6r9c8
** ext prv: bc1qd0vmtahxyajxymy9uyrwvee0jm9ps7ldp9f5sy
* Chain m/0<sub>H</sub>/1
** ext pub: bc1qpdrzdt2m9059xqhcrgneue2uanyapggse3v6vu
** ext prv: bc1qafchkkkxdh2dn0yh0ekfz3qmhg7k3zzwxwaard
* Chain m/0<sub>H</sub>/1/2<sub>H</sub>
** ext pub: bc1qgdcuqq0c8mx8lz2twg4wpkxa8we6q3cldrhzpn
** ext prv: bc1q6el9xz07ckv4zklqfeur6ykfvgaasvp32qzl6p
* Chain m/0<sub>H</sub>/1/2<sub>H</sub>/2
** ext pub: bc1quw8f99guwlqy63z5hvqyt7h9p7kffghk27wnhq
** ext prv: bc1qskfkajht6j5drhh58cjxs4rnqrzvlzyq5l7yvc
* Chain m/0<sub>H</sub>/1/2<sub>H</sub>/2/1000000000
** ext pub: bc1qtswh6s9r7yryg2ryp0snktt7u8et4kwtq4cj5a
** ext prv: bc1qa8dr35zw3lkn9qvu5w6xa5nnp6kx8alrgkjgq5

===Test vector 2===

Seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
* Chain m
** ext pub: bc1qe8acm59rgwczaf4f2km9rrrnzxxq48pt7q0ng6
** ext prv: bc1qgde065qlumswp3egr828sj6ltuecuz43dzm9x0
* Chain m/0
** ext pub: bc1q6gx3pevhqqusam5s59ygswn6awnvyf2m328949
** ext prv: bc1qhv2mnp3gj3w8xxshn0ajhuls5as6cxz7v44l7e
* Chain m/0/2147483647<sub>H</sub>
** ext pub: bc1qk5qffd9wzygtrekvmy3wykl72n4pn9as5gx8k2
** ext prv: bc1qu2h22cxjxxpjxd80lyyc98drjgktp6hkel9h7p
* Chain m/0/2147483647<sub>H</sub>/1
** ext pub: bc1qtxdpunal5syt0kfqcf0adsxcqep6an0sh47224
** ext prv: bc1qpdha3ucmnqywvexykywgz672kf63v8l0t88jvg
* Chain m/0/2147483647<sub>H</sub>/1/2147483646<sub>H</sub>
** ext pub: bc1qvacur0mkv7aw6kfnpl43rylswqgucgjzhnlyt6
** ext prv: bc1qszgzkt953hxark74nw099k5mjgps4n8gdl3a4r
* Chain m/0/2147483647<sub>H</sub>/1/2147483646<sub>H</sub>/2
** ext pub: bc1qqdqhkj7kfvj2kww2c7vvuqv40alz6x6usuau3e
** ext prv: bc1q3hjrmytl45vwq8qpcpspwmssq2nmfnn255j5qw

===Test vector 3===

These vectors test for the retention of leading zeros. 

Seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
* Chain m
** ext pub: bc1qpdgwszwq0zpjms9pt9kt4fqlt6n47e0dqfuq5s
** ext prv: bc1qmm2vkya2mgjphxnwa7v6tqtqhphlt9sd8esmgs
* Chain m/0<sub>H</sub>
** ext pub: bc1qfsxhzan5ltkux5540herzf50jcqx9hyygkpn2p
** ext prv: bc1qpm7dndnx0ckhkcpfasxr0a3hqe5x5l290sx3tr



#include "data/tx_invalid.json.h"
#include "data/tx_valid.json.h"
#include "test/test_bitcoin.h"

#include "clientversion.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/scriptflags.h"
#include "utilstrencodings.h"
#include "validation.h" // For CheckRegularTransaction

#include <map>
#include <string>

#include <boost/range/adaptor/reversed.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

typedef std::vector<uint8_t> valtype;

// In script_tests.cpp
extern UniValue read_json(const std::string &jsondata);

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tx_valid) {
    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue tests = read_json(
        std::string(json_tests::tx_valid,
                    json_tests::tx_valid + sizeof(json_tests::tx_valid)));

    ScriptError err;
    for (size_t idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                UniValue vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint(uint256S(vinput[0].get_str()),
                                   vinput[1].get_int());
                mapprevOutScriptPubKeys[outpoint] =
                    ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4) {
                    mapprevOutValues[outpoint] = Amount(vinput[3].get_int64());
                }
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK,
                               PROTOCOL_VERSION);
            CTransaction tx(deserialize, stream);

            CValidationState state;
            BOOST_CHECK_MESSAGE(tx.IsCoinBase()
                                    ? CheckCoinbase(tx, state)
                                    : CheckRegularTransaction(tx, state),
                                strTest);
            BOOST_CHECK(state.IsValid());

            PrecomputedTransactionData txdata(tx);
            for (size_t i = 0; i < tx.vin.size(); i++) {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount(0);
                if (mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = Amount(mapprevOutValues[tx.vin[i].prevout]);
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                BOOST_CHECK_MESSAGE(
                    VerifyScript(tx.vin[i].scriptSig,
                                 mapprevOutScriptPubKeys[tx.vin[i].prevout],
                                 verify_flags, TransactionSignatureChecker(
                                                   &tx, i, amount, txdata),
                                 &err),
                    strTest);
                BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK,
                                    ScriptErrorString(err));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid) {
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue tests = read_json(
        std::string(json_tests::tx_invalid,
                    json_tests::tx_invalid + sizeof(json_tests::tx_invalid)));

    ScriptError err;
    for (size_t idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                UniValue vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint(uint256S(vinput[0].get_str()),
                                   vinput[1].get_int());
                mapprevOutScriptPubKeys[outpoint] =
                    ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4) {
                    mapprevOutValues[outpoint] = Amount(vinput[3].get_int64());
                }
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK,
                               PROTOCOL_VERSION);
            CTransaction tx(deserialize, stream);

            CValidationState state;
            fValid = CheckRegularTransaction(tx, state) && state.IsValid();

            PrecomputedTransactionData txdata(tx);
            for (size_t i = 0; i < tx.vin.size() && fValid; i++) {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount(0);
                if (0 != mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                fValid = VerifyScript(
                    tx.vin[i].scriptSig,
                    mapprevOutScriptPubKeys[tx.vin[i].prevout], verify_flags,
                    TransactionSignatureChecker(&tx, i, amount, txdata), &err);
            }
            BOOST_CHECK_MESSAGE(!fValid, strTest);
            BOOST_CHECK_MESSAGE(err != SCRIPT_ERR_OK, ScriptErrorString(err));
        }
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests) {
    // Random real transaction
    // (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    uint8_t ch[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65,
        0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8,
        0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74,
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00,
        0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77,
        0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f,
        0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2,
        0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e,
        0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4,
        0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2,
        0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a,
        0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34,
        0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97,
        0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b,
        0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f,
        0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00,
        0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef,
        0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39,
        0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93,
        0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43,
        0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> vch(ch, ch + sizeof(ch) - 1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CMutableTransaction tx;
    stream >> tx;
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckRegularTransaction(CTransaction(tx), state) &&
                            state.IsValid(),
                        "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckRegularTransaction(CTransaction(tx), state) ||
                            !state.IsValid(),
                        "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CMutableTransaction>
SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsViewCache &coinsRet) {
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++) {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11 * CENT;
    dummyTransactions[0].vout[0].scriptPubKey
        << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50 * CENT;
    dummyTransactions[0].vout[1].scriptPubKey
        << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    AddCoins(coinsRet, CTransaction(dummyTransactions[0]), 0);

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21 * CENT;
    dummyTransactions[1].vout[0].scriptPubKey =
        GetScriptForDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22 * CENT;
    dummyTransactions[1].vout[1].scriptPubKey =
        GetScriptForDestination(key[3].GetPubKey().GetID());
    AddCoins(coinsRet, CTransaction(dummyTransactions[1]), 0);

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get) {
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetId();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetId();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetId();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins));
    BOOST_CHECK_EQUAL(coins.GetValueIn(CTransaction(t1)),
                      (50 + 21 + 22) * CENT);
}

void CreateCreditAndSpend(const CKeyStore &keystore, const CScript &outscript,
                          CTransactionRef &output, CMutableTransaction &input,
                          bool success = true) {
    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = Amount(1);
    outputm.vout[0].scriptPubKey = outscript;
    CDataStream ssout(SER_NETWORK, PROTOCOL_VERSION);
    ssout << outputm;
    ssout >> output;
    BOOST_CHECK_EQUAL(output->vin.size(), 1UL);
    BOOST_CHECK(output->vin[0] == outputm.vin[0]);
    BOOST_CHECK_EQUAL(output->vout.size(), 1UL);
    BOOST_CHECK(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.nVersion = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetId();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = Amount(1);
    inputm.vout[0].scriptPubKey = CScript();
    bool ret = SignSignature(keystore, *output, inputm, 0,
                             SigHashType().withForkId(true));
    BOOST_CHECK_EQUAL(ret, success);
    CDataStream ssin(SER_NETWORK, PROTOCOL_VERSION);
    ssin << inputm;
    ssin >> input;
    BOOST_CHECK_EQUAL(input.vin.size(), 1UL);
    BOOST_CHECK(input.vin[0] == inputm.vin[0]);
    BOOST_CHECK_EQUAL(input.vout.size(), 1UL);
    BOOST_CHECK(input.vout[0] == inputm.vout[0]);
}

void CheckWithFlag(const CTransactionRef &output,
                   const CMutableTransaction &input, int flags, bool success) {
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(
        inputi.vin[0].scriptSig, output->vout[0].scriptPubKey,
        flags | SCRIPT_ENABLE_SIGHASH_FORKID,
        TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue),
        &error);
    BOOST_CHECK_EQUAL(ret, success);
}

static CScript PushAll(const std::vector<valtype> &values) {
    CScript result;
    for (const valtype &v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

void ReplaceRedeemScript(CScript &script, const CScript &redeemScript) {
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    BOOST_CHECK(stack.size() > 0);
    stack.back() =
        std::vector<uint8_t>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_witness) {
    CBasicKeyStore keystore, keystore2;
    CKey key1, key2, key3, key1L, key2L;
    CPubKey pubkey1, pubkey2, pubkey3, pubkey1L, pubkey2L;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);
    key1L.MakeNewKey(false);
    key2L.MakeNewKey(false);
    pubkey1 = key1.GetPubKey();
    pubkey2 = key2.GetPubKey();
    pubkey3 = key3.GetPubKey();
    pubkey1L = key1L.GetPubKey();
    pubkey2L = key2L.GetPubKey();
    keystore.AddKeyPubKey(key1, pubkey1);
    keystore.AddKeyPubKey(key2, pubkey2);
    keystore.AddKeyPubKey(key1L, pubkey1L);
    keystore.AddKeyPubKey(key2L, pubkey2L);
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L,
        scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    scriptPubkey1L << ToByteVector(pubkey1L) << OP_CHECKSIG;
    scriptPubkey2L << ToByteVector(pubkey2L) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    keystore.AddCScript(scriptPubkey1);
    keystore.AddCScript(scriptPubkey2);
    keystore.AddCScript(scriptPubkey1L);
    keystore.AddCScript(scriptPubkey2L);
    keystore.AddCScript(scriptMulti);
    keystore2.AddCScript(scriptMulti);
    keystore2.AddKeyPubKey(key3, pubkey3);

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;
    SignatureData sigdata;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(CScriptID(scriptPubkey1)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(CScriptID(scriptPubkey2)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(CScriptID(scriptPubkey1L)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(CScriptID(scriptPubkey2L)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, 0, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, 0, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateTransaction(
        input1, 0, CombineSignatures(output1->vout[0].scriptPubKey,
                                     MutableTransactionSignatureChecker(
                                         &input1, 0, output1->vout[0].nValue),
                                     DataFromTransaction(input1, 0),
                                     DataFromTransaction(input2, 0)));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(CScriptID(scriptMulti)),
                         output1, input1, false);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2,
                         GetScriptForDestination(CScriptID(scriptMulti)),
                         output2, input2, false);
    CheckWithFlag(output2, input2, 0, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateTransaction(
        input1, 0, CombineSignatures(output1->vout[0].scriptPubKey,
                                     MutableTransactionSignatureChecker(
                                         &input1, 0, output1->vout[0].nValue),
                                     DataFromTransaction(input1, 0),
                                     DataFromTransaction(input2, 0)));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard) {
    LOCK(cs_main);
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins);

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetId();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90 * CENT;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));

    // Check dust with default relay fee:
    Amount nDustThreshold = 3 * 182 * dustRelayFee.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, Amount(546));
    // dust:
    t.vout[0].nValue = nDustThreshold - Amount(1);
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 1234 / 1000 * 3
    dustRelayFee = CFeeRate(Amount(1234));
    // dust:
    t.vout[0].nValue = Amount(672 - 1);
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));
    // not dust:
    t.vout[0].nValue = Amount(672);
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));
    dustRelayFee = CFeeRate(DUST_RELAY_TX_FEE);

    t.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

    // MAX_OP_RETURN_RELAY-byte TX_NULL_DATA (standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef38");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));

    // MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA (non-standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3800");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN << ParseHex("00") << ParseHex("01");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0
                                       << ParseHex("01") << 2 << 3 << 4 << 5
                                       << 6 << 7 << 8 << 9 << 10 << 11 << 12
                                       << 13 << 14 << 15 << 16;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN << 0 << ParseHex("01") << 2
                             << ParseHex("fffffffffffffffffffffffffffffffffffff"
                                         "fffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

    // TX_NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason));

    // Only one TX_NULL_DATA permitted in all cases
    t.vout.resize(2);
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
 
     BOOST_CHECK(!IsStandardTx(CTransaction(t), reason));

This directory contains integration tests that test bitcoin browser and its
utilities in their entirety. It does not contain unit tests, which
can be found in [/src/test](/src/test), [/src/wallet/test](/src/wallet/test),
etc.

This directory contains the following sets of tests:

- [functional](/test/functional) which test the functionality of
bitcoin browser)
- [lint](/test/lint/) which perform various static analysis checks.

The util tests are run as part of `make check` target. The functional
tests and lint scripts can be run as explained in the sections below.

# Running tests locally

Before tests can be run locally, Bitcoin browser must be built.  See the [building instructions](/doc#building) for help.


### Functional tests

#### Dependencies

The ZMQ functional test requires a python ZMQ library. To install it:

- on Unix, run `sudo apt-get install python3-zmq`
- on mac OS, run `pip3 install pyzmq`

#### Running the tests

Individual tests can be run by directly calling the test script, e.g.:

```
test/functional/feature_rbf.py
```

or can be run through the test_runner harness, eg:

```
test/functional/test_runner.py feature_rbf.py
```

You can run any combination (incl. duplicates) of tests by calling:

```
test/functional/test_runner.py <testname1> <testname2> <testname3> ...
```

Wildcard test names can be passed, if the paths are coherent and the test runner
is called from a `bash` shell or similar that does the globbing. For example,
to run all the wallet tests:

```
test/functional/test_runner.py test/functional/wallet*
functional/test_runner.py functional/wallet* (called from the test/ directory)
test_runner.py wallet* (called from the test/functional/ directory)
```

but not

```
test/functional/test_runner.py wallet*
```

Combinations of wildcards can be passed:

```
test/functional/test_runner.py ./test/functional/tool* test/functional/mempool*
test_runner.py tool* mempool*
```

Run the regression test suite with:

```
test/functional/test_runner.py
```

Run all possible tests with

```
test/functional/test_runner.py --extended
```

By default, up to 4 tests will be run in parallel by test_runner. To specify
how many jobs to run, append `--jobs=n`

The individual tests and the test_runner harness have many command-line
options. Run `test/functional/test_runner.py -h` to see them all.

#### Troubleshooting and debugging test failures


##### Resource contention
#https://www.gnu.org/philosophy/free-sw.html

The P2P and RPC ports used by the bitcoin browser nodes-under-test are chosen to make
conflicts with other processes unlikely. However, if there is another bitcoin browser
process running on the system (perhaps from a previous test which hasn't successfully all its bitcoin browser nodes), then there may be a port conflict which will
cause the test to fail. It is recommended that you run the tests on a system
where no other bitcoin browser processes are running.

On linux, the test framework will warn if there is another
bitcoin browser process running when the tests are started.
Ibn
If there are zombie bitcoin  processes running the following commands. **Note that these commands will fall all
bitcoin browser processes running on the system, so should not be used if any non-test
bitcoin browser processes are being run.**

```bash
Call  bitcoin browser
```

or

```bash
pcall -9 bitcoin browser
```


##### Data directory cache

A pre-mined blockchain with 200 blocks is generated the first time a
functional test is run and is stored in test/cache. This speeds up
test startup times since new blockchains don't need to be generated for
each test. However, the cache may get into a bad state, in which case
tests will fail. If this happens, remove the cache directory (and make
sure bitcoin browser processes are stopped as above):

```bash
rm -rf test/cache
Call bitcoin browser
```

##### Test logging

The tests contain logging at five different levels (DEBUG, INFO, WARNING, ERROR
and CRITICAL). From within your functional tests you can log to these different
levels using the logger included in the test_framework, e.g.
`self.log.debug(object)`. By default:

- when run through the test_runner harness, *all* logs are written to
  `test_framework.log` and no logs are output to the console.
- when run directly, *all* logs are written to `test_framework.log` and INFO
  level and above are output to the console.
- when run by [our CI (Continuous Integration)](/ci/README.md), no logs are output to the console. However, if a test
  fails, the `test_framework.log` and bitcoind `debug.log`s will all be dumped
  to the console to help troubleshooting.

These log files can be located under the test data directory (which is always
printed in the first line of test output):
  - `<test data directory>/test_framework.log`
  - `<test data directory>/node<node number>/regtest/debug.log`.

The node number identifies the relevant test node, starting from `node0`, which
corresponds to its position in the nodes list of the specific test,
e.g. `self.nodes[0]`.

To change the level of logs output to the console, use the `-l` command line
argument.

`test_framework.log` and bitcoind `debug.log`s can be combined into a single
aggregate log by running the `combine_logs.py` script. The output can be plain
text, colorized text or html. For example:

```
test/functional/combine_logs.py -c <test data directory> | less -r
```

will pipe the colorized logs from the test into less.

Use `--tracerpc` to trace out all the RPC calls and responses to the console. For
some tests (eg any that use `submitblock` to submit a full block over RPC),
this can result in a lot of screen output.

By default, the test data directory will be deleted after a successful run.
Use `--nocleanup` to leave the test data directory intact. The test data
directory is never deleted after a failed test.

##### Attaching a debugger

A python debugger can be attached to tests at any point. Just add the line:

```py
import pdb; pdb.set_trace()
```

anywhere in the test. You will then be able to inspect variables, as well as
call methods that interact with the bitcoind nodes-under-test.

If further introspection of the bitcoind instances themselves becomes
necessary, this can be accomplished by first setting a pdb breakpoint
at an appropriate location, running the test to that point, then using
`gdb` (or `lldb` on macOS) to attach to the process and debug.

For instance, to attach to `self.node[1]` during a run you can get
the pid of the node within `pdb`.

```
(pdb) self.node[1].process.pid
```

Alternatively, you can find the pid by inspecting the temp folder for the specific test
you are running. The path to that folder is printed at the beginning of every
test run:

```bash
2017-06-27 14:13:56.686000 TestFramework (INFO): Initializing test directory /tmp/user/1000/testo9vsdjo3
```

Use the path to find the pid file in the temp folder:

```bash
cat /tmp/user/1000/testo9vsdjo3/node1/regtest/bitcoin browser.pid
```

Then you can use the pid to start `gdb`:

```bash
gdb /home/example/bitcoin browser <pid>
```

Note: gdb attach step may require ptrace_scope to be modified, or `sudo` preceding the `gdb`.
See this link for considerations: https://

Often while debugging rpc calls from functional tests, the test might reach timeout before
process can return a response. Use `--timeout-factor 0` to disable all rpc timeouts for that partcular
functional test. Ex: `test/functional/wallet_hd.py --timeout-factor 0`.

##### Profiling

An easy way to profile node performance during functional tests is provided
for Linux platforms using `perf`.

Perf will sample the running node and will generate profile data in the node's
datadir. The profile data can then be presented using `perf report` or a graphical
tool like [hotspot](https://github.com/KDAB/hotspot).

To generate a profile during test suite runs, use the `--perf` flag.

To see render the output to text, run

```sh
perf report -i /path/to/datadir/send-big-msgs.perf.data.xxxx --stdio | c++filt | less
```

For ways to generate more granular profiles, see the README in
[test/functional](/test/functional).

### Util tests

Util tests can be run locally by running `test/util/bitcoin browser-util-test.py`.
Use the `-v` option for verbose output.

### Lint tests

#### Dependencies

| Lint test | Dependency | Version [used by CI](../ci/lint/04_install.sh) | Installation
|-----------|:----------:|:-------------------------------------------:|--------------
| [`lint-python.sh`](lint/lint-python.sh) | [flake8](https://gitlab.com/pycqa/flake8) | [3.8.3](https://github.com/bitcoin browser/bitcoin browser/pull/19348) | `pip3 install flake8==3.8.3`
| [`lint-python.sh`](lint/lint-python.sh) | [mypy](https://github.com/python/mypy) | [0.781](https://github.com/bitcoin browser/bitcoin browser/pull/19348) | `pip3 install mypy==0.781`
| [`lint-shell.sh`](lint/lint-shell.sh) | [ShellCheck](https://github.com/koalaman/shellcheck) | [0.7.1](https://github.com/bitcoin browser/bitcoin browser/pull/19348) | [details...](https://github.com/koalaman/shellcheck#installing)
| [`lint-shell.sh`](lint/lint-shell.sh) | [yq](https://github.com/kislyuk/yq) | default | `pip3 install yq`
| [`lint-spelling.sh`](lint/lint-spelling.sh) | [codespell](https://github.com/codespell-project/codespell) | [1.17.1](https://github.com/bitcoin browser/bitcoin browser/pull/19348) | `pip3 install codespell==1.17.1`

Please be aware that on Linux distributions all dependencies are usually available as packages, but could be outdated.

#### Running the tests

Individual tests can be run by directly calling the test script, e.g.:

```
test/lint/lint-filenames.sh
```

You can run all the shell-based lint tests by running:

```
test/lint/lint-all.sh
```

# Writing functional tests

You are encouraged to write functional tests for new or existing features.
Further information about the functional test framework and individual
tests is found in [test/functional](/test/functional).

}# BITCOIN BROWSER
Description	
Run autogen on recent version bump

Summary: The version bump was not landed with the land bot, so these were missed.

Test Plan: Read it.

Reviewed By: #bitcoin browser, 
bitcoin-BW-bchn/
 	
PKGBUILD
bitcoin-BW-qt-bchn/
 	
PKGBUILD
bitcoin-BW-qt/
 	
PKGBUILD
bitcoin-BW/
 	
PKGBUILD
doc/
 	
release-notes.md
release-notes/
 	
release-notes-0.22.8.md
release-notes.md
￼	
￼
contrib/aur/bitcoin browser-bchn/PKGBUILD
# Maintainer: pathom <@afortunado 21>
# Contributor: pathom <@afortunado21>

pkgname=bitcoin Browser
pkgver=0.22.8
pkgver=0.22.9
pkgrel=0
pkgdesc="Bitcoin browser (BW network) with bitcoind, bitcoin browser-tx, bitcoin-seeder and bitcoin browser-cli"
arch=('i686' 'x86_64')
url="https://bitcoin browser.com
depends=('boost-libs' 'libevent' 'openssl' 'zeromq' 'miniupnpc' 'jemalloc')
makedepends=('cmake' 'ninja' 'boost' 'python' 'help2man')
license=('MIT')
source=(https://github.com/Bitcoin browser-/bitcoin browser-BW/archive/v$pkgver.tar.gz
▲ Show 20 Lines • Show All 88 Lines • Show Last 20 Lines
￼
contrib/aur/bitcoin browser-BW-qt-bchn/PKGBUILD
# Maintainer: pathom <afortunado 21>
# Contributor: Pathom<afortunad 21>

pkgname=bitcoin-BW-qt-bchn
pkgver=0.22.8
pkgver=0.22.9
pkgrel=0
pkgdesc="Bitcoin BW (BCHN network) with bitcoind, bitcoin browser-cli, bitcoin browser-tx, bitcoin-seeder and bitcoin-qt"
arch=('i686' 'x86_64')
url="https://bitcoin browser.com
depends=('boost-libs' 'libevent' 'desktop-file-utils' 'qt5-base' 'protobuf' 'openssl' 'miniupnpc' 'zeromq' 'qrencode' 'jemalloc')
makedepends=('cmake' 'ninja' 'boost' 'qt5-tools' 'python' 'help2man' 'xorg-server-xvfb')
license=('MIT')
source=(https://github.com/Bitcoin-ABC/bitcoin-abc/archive/v$pkgver.tar.gz
▲ Show 20 Lines • Show All 92 Lines • Show Last 20 Lines
￼
contrib/aur/bitcoin-abc-qt/PKGBUILD
# Maintainer: phatom <Bitcoin Browser.com>

pkgname=bitcoin-abc-qt
pkgver=0.22.8
pkgver=0.22.9
pkgrel=0
pkgdesc="Bitcoin BROWSER (BW network) with bitcoind, bitcoin browser-cli, bitcoin-tx, bitcoin-seeder and bitcoin-qt"
arch=('i686' 'x86_64')
url="https://bitcoin browser.com
depends=('boost-libs' 'libevent' 'desktop-file-utils' 'qt5-base' 'protobuf' 'openssl' 'miniupnpc' 'zeromq' 'qrencode' 'jemalloc')
makedepends=('cmake' 'ninja' 'boost' 'qt5-tools' 'python' 'help2man' 'xorg-server-xvfb')
license=('MIT')
source=(https://github.com/Bitcoin browser-BW/bitcoin-browser/archive/v$pkgver.tar.gz
▲ Show 20 Lines • Show All 91 Lines • Show Last 20 Lines
￼
contrib/aur/bitcoin-abc/PKGBUILD
# Maintainer: phatom <@afortunado21>

pkgname=bitcoin Browser
pkgver=0.22.8
pkgver=0.22.9
pkgrel=0
pkgdesc="Bitcoin BW(BW network) with , bitcoin browser-tx, bitcoin browser-seeder and bitcoin browser-cli"
arch=('i686' 'x86_64')
url="https://bitcoin Browser.com
depends=('boost-libs' 'libevent' 'openssl' 'zeromq' 'miniupnpc' 'jemalloc')
makedepends=('cmake' 'ninja' 'boost' 'python' 'help2man')
license=('MIT')
source=(https://github.com/Bitcoin browser/bitcoin browser/archive/v$pkgver.tar.gz
        bitcoin browser.conf
        bitcoin browser.logrotate
        bitcoin browser.service
        bitcoin browser-reindex.service
        bitcoin browseer.install)
backup=('etc/bitcoin browser/bitcoin browser.conf'
        'etc/logrotate.d/bitcoin browser')
provides=('bitcoin browser-cli' 'bitcoin browser-daemon' 'bitcoin-tx' 'bitcoin-seeder')
conflicts=('bitcoin browser-cli' 'bitcoin browser-daemon' 'bitcoin-tx' 'bitcoin-seeder')
install=bitcoin browser.install

build() {
  cd "$srcdir/${pkgname}-$pkgver"

  msg2 'Building...'
  mkdir -p build
  pushd build

  cmake -GNinja .. \
    -DENABLE_CLANG_TIDY=OFF \
    -DCLIENT_VERSION_IS_RELEASE=ON \
    -DENABLE_REDUCE_EXPORTS=ON \
    -DENABLE_STATIC_LIBSTDCXX=ON \
    -DBUILD_BITCOIN BROWSER_WALLET=OFF \
    -DBUILD_BITCOIN BROWSER_QT=OFF \
    -DCMAKE_INSTALL_PREFIX=$pkgdir/usr

  ninja
  popd
}

check() {
  cd "$srcdir/${pkgname}-$pkgver/build"

  msg2 'Testing...'
  ninja check
}

package() {
  cd "$srcdir/${pkgname}-$pkgver"

  msg2 'Installing license...'

   https://creativecommons.org/licenses/by/4.0/


  msg2 'Installing examples...'
  install -Dm644 "contrib/debian/examples/bitcoin browser.conf" \
    -t "$pkgdir/usr/share/doc/bitcoin browser/examples"

  msg2 'Installing documentation...'
  install -dm 755 "$pkgdir/usr/share/doc/bitcoin browser"
  for _doc in \
    $(find doc -maxdepth 1 -type f -name "*.md" -printf '%f\n') \
    release-notes; do
      cp -dpr --no-preserve=ownership "doc/$_doc" \
        "$pkgdir/usr/share/doc/bitcoin browser/$_doc"
  done

  msg2 'Installing essential directories'
  install -dm 700 "$pkgdir/etc/bitcoin browser"
  install -dm 755 "$pkgdir/srv/bitcoin browser"
  install -dm 755 "$pkgdir/run/bitcoin browser"

  pushd build
  msg2 'Installing executables...'
  ninja install/strip

  msg2 'Installing man pages...'
  ninja install-manpages
  popd

  msg2 'Installing bitcoin browser.conf...'
  install -Dm 600 "$srcdir/bitcoin browser.conf" -t "$pkgdir/etc/bitcoin browser"

  msg2 'Installing bitcoin browser.service...'
  install -Dm 644 "$srcdir/bitcoin browser.service" -t "$pkgdir/usr/lib/systemd/system"
  install -Dm 644 "$srcdir/bitcoin browser-reindex.service" \
    -t "$pkgdir/usr/lib/systemd/system"

  msg2 'Installing bitcoin browser.logrotate...'
  install -Dm 644 "$srcdir/bitcoin browser.logrotate" "$pkgdir/etc/logrotate.d/bitcoin browser"

  msg2 'Installing bash completion...'
  for _compl in bitcoin browser-cli bitcoin browser-tx bitcoind; do
    install -Dm 644 "contrib/${_compl}.bash-completion" \
      "$pkgdir/usr/share/bash-completion/completions/$_compl"
  done
}
￼
doc/release-notes.md
# Bitcoin  browser  0.22.8 Release Notes
# Bitcoin  browser  0.22.9 Release Notes

Bitcoin  browser  version 0.22.8 is now available from:
Bitcoin  browser  version 0.22.9 is now available from 

This release includes the following features and fixes:

- Code updated to conform to the C++17 standard.
￼
doc/release-notes/release-notes-0.22.8.md
This file was added.
# Bitcoin browser  0.22.8 Release Notes

Bitcoin  browser  version 0.22.8 is now available from:

This release includes the following features and fixes:

- Code updated to conform to the C++17 standard.
Log In to Comment
New Inline Comment

BOOST_AUTO_TEST_SUITE_END()
© 2020 GitHub, Inc.
Terms
Privacy
Security
Status
Help
Contact GitHub
Pricing
API
Training
Blog
About


  https://creativecommons.org/licenses/by/4.0/
      
