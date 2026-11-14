# namecage

A lab path validator for HMAC-signed JSON certificates, with name constraints, pathLen, EKU nesting, and policy OIDs.

`python -m namecage inspect --bundle fixtures/bundles/ok-chain.json` already prints subjects. `admit` is still a stub.

Standard library only. No Docker, no PEM/ASN.1 libraries.
