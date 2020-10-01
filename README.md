# Critical Manufacturing Security Portal Nexus3 Plugin
This plugin adds a realm to Sonatype Nexus OSS and enables you to authenticate with Critical Manufacturing Security Portal.

The plugin does not implement a full OAuth flow, instead you use your user account + a Personal Access Token you generated in your account to log in to the nexus.
This works through the web as well as through tools like docker, maven, gradle etc.

## Setup

### 1. Activate the Realm
Log in to your nexus and go to _Administration > Security > Realms_. Move the Critical Manufacturing Realm to the right. The realm order in the form determines the order of the realms in your authentication flow. We recommend putting this realm _after_ the built-in realms:

### 2. Group / Roles Mapping
When logged in through Security Portal, all roles the user is a member of will be mapped into nexus roles like so:

You need to create these roles in nexus.
To manually create them: _Administration > Security > Roles > (+) Create Role > Nexus Role_ in order to assign them the desired privileges. The _Role ID_ should map to the _Role.Name_ in Critical Manufacturing.
Note that by default everybody can log in (authenticate) with a valid Critical Manufacturing PAT from your Critical Manufacturing instance, but he/she won't have any privileges assigned with their roles (authorization).

## Usage

The following steps need to be done by every developer who wants to login to your nexus with Critical Manufacturing Security Portal.

### 1. Generate Personal Access Token

In your Critical Manufacturing instance under _User Profile > Access Tokens_ to generate a new token.
If you don't have permissions to do so, please ask your instance Administrator.

### 2. Login to nexus

When logging in to nexus, use your Critical Manufacturing user account as the user name, and the PAT token you just generated as the password.
This also works through docker, npm, maven, gradle etc.

#### Example Docker login

```shell script
docker login -u 'Your User Account' -p 'Your Personal Access Token' criticalmanufacturing.io
```

#### Example Maven settings.xml fragment

```xml
<servers>
  <server>
    <id>Id that matches the id element of the repository/mirror that Maven tries to connect to</id>
    <username>Your User Account</username>
    <password>Your Personal Access Token</password>
  </server>
</servers>
```
