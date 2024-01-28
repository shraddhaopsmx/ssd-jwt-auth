# ssd-jwt-auth
Repo to implement the SSD service-to-service JWT-auth package

https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit

All services in SSD authenticate with JWTs.

Communications fall in these categories:
a) External systems to services within SSD :These will typically go through the ssd-gate where they will be authenticated
b) SSD services to other SSD Services: These will use the "internal-account" type to increase the priviledges Or can use the token received to support a call
c) UI to SSD-Gate: As secure cookie is already implemented, we will continue to use it till it is changed to JWT

Token creation:
a) UI will provide options to create tokens specific to an integration or a generic user token can be used in automation
b) Library will provide ability to create Internal JWTs only. It will need to be authenticated by an existing JWT
