# keycloak-custom
A place to track my objectives and customization of keycloak

## Keycloak Objectives

- Custom Security Questions
- Enhanced Terms of Service, by client, by roles/groups
- Username Policy
- Custom Password Policy
- Login form with username and email and password required and validated
- Minimum password lifetime policy
- Custom BruteForceProtector
- Lockout inactive accounts by timeframe
- 2factor SMS
- geolocation aware and fraud detection

## RH Atomic Host Environment
2 nodes with RH-SSO server
1 node with postgres database
2 nodes with test application EAP7 / Java EE
1 node with an IPA server / Red Hat Directory Services
1 node with MS Windows Server and Active Directory
1 node with spring boot application

1 node with jmeter test script running, from a separate subnet

base install rhel 7 server

subscription-manager register
subscription-manager attach --pool=$POOL_ID
yum install vim
subscription-manager repos --enable=jb-eap-7.0-for-rhel-7-server-rpms
subscription-manager repos --enable=rh-sso-7.1-for-rhel-7-server-rpms
sudo yum groupinstall rh-sso7

firewall-cmd --add-service=http,https
firewall-cmd --add-port=8080/tcp,8443/tcp
firewall-cmd --permanent --add-port=8443/tcp
firewall-cmd --permanent --add-port=8080/tcp
