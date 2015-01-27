#Dynamic Group Signature library

This is the repository for Dynamic Group Signature by Camenisch-Lysyanskaya scheme.

###External dependencies:
Your system should have GMP lib 6.0.0 and PBC lib 0.5.14.
###Configuration
Pairing parameters was defined to default as PBClib example.
###How it works
Dynamic Group Signature Scheme

This scheme involves three types of participants:
```
group manger
group member
verifier
```
A dynamic group signature scheme consists of five polynomial-time algorithms/protocols:

1. Key generation.
```
Generation of group public key, member's secret issuer key and member's secret opener key.
```

2. Join protocol.
```
Registration of new group users, as a result, each user receives a own secret key from manager, who knows the secret issuer key.
```

3. Signature generation.
```
Each member of group with own secret key can produce the group signature on default message on behalf of group.
```

4. Signature verification.
```
Everyone who know group public key can verify the group signature.
```

5. Opening procedure.
```
Only group manager with secret opener key can open who is a singer on default group signature.
```
