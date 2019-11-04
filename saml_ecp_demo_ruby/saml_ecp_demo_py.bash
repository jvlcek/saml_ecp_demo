#!/usr/bin/env bash  

python3 saml_ecp_demo.py \
  --log-categories "http-lowlevel,sp-resource,http-content,saml-message,message-info,http-request-response" \
  --log-file ./saml_ecp_demo.log \
  --sp-resource https://joev-saml/saml_login \
  --idp-endpoint http://joev-keycloak:8080/auth/realms/miq/protocol/saml \
  --user jvlcek \
  --password smartvm \
  --show-traceback
