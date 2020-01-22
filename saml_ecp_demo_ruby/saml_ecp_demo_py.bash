#!/usr/bin/env bash  

python3 saml_ecp_demo.py \
  --log-categories "http-lowlevel,sp-resource,http-content,saml-message,message-info,http-request-response,message-info,saml-message" \
  --log-file ./saml_ecp_demo.log \
  --sp-resource https://joev-saml.jvlcek.redhat.com/saml_login \
  --idp-endpoint http://joev-keycloak.jvlcek.redhat.com:8080/auth/realms/miq/protocol/saml \
  --user jvlcek \
  --password smartvm \
  --show-traceback
