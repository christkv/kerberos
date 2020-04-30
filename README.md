Kerberos
========
[![Build Status](https://travis-ci.org/mongodb-js/kerberos.svg?branch=master)](https://travis-ci.org/mongodb-js/kerberos)

The `kerberos` package is a C++ extension for Node.js that provides cross-platform support for kerberos authentication using GSSAPI on linux/osx, and SSPI on windows. Much of the code in this module is adapted from [ccs-kerberos](https://github.com/apple/ccs-pykerberos) and [winkerberos](https://github.com/mongodb-labs/winkerberos).

### Requirements

**Linux**
- `python` v2.7
- `make`
- A proper C/C++ compiler toolchain, like [GCC](https://gcc.gnu.org/)
- Distribution-specific kerberos packages (e.g. `krb5-dev` on Ubuntu)

**macOS**
- `Xcode Command Line Tools`: Can be installed with `xcode-select --install`
- Distribution-specific kerberos packages (e.g. `krb5` on Homebrew)

**Windows**
- **Option 1:** Install all the required tools and configurations using Microsoft's [windows-build-tools](https://github.com/felixrieseberg/windows-build-tools) by running `npm install -g windows-build-tools` from an elevated PowerShell (run as Administrator).
- **Option 2:** Install dependencies and configuration manually
   1. Visual C++ Build Environment:
     * **Option 1:** Install [Visual C++ Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126) using the *Default Install* option.
     * **Option 2:** Install [Visual Studio 2015](https://www.visualstudio.com/products/visual-studio-community-vs) (or modify an existing installation) and select *Common Tools for Visual C++* during setup.

  > :bulb: [Windows Vista / 7 only] requires [.NET Framework 4.5.1](http://www.microsoft.com/en-us/download/details.aspx?id=40773)

  2. Install [Python 2.7](https://www.python.org/downloads/) or [Miniconda 2.7](http://conda.pydata.org/miniconda.html) (`v3.x.x` is not supported), and run `npm config set python python2.7`
  3. Launch cmd, `npm config set msvs_version 2015`

**z/OS**
- Install [IBM SDK for node.js v12.16.1 or later](https://www.ibm.com/ca-en/marketplace/sdk-nodejs-compiler-zos/purchase).
- Install krb5 libraries for z/OS (which requires [curl for z/OS](https://www.rocketsoftware.com/product-categories/mainframe/curl-for-zos) and [gzip for z/OS](https://www.rocketsoftware.com/product-categories/mainframe/gzip-zos)):
```
_ENCODE_FILE_NEW=BINARY curl https://codeload.github.com/ibmruntimes/libkrb5-zos/tar.gz/v1.16.3-zos --output v1.16.3-zos.tar.gz
gzip -d v1.16.3-zos.tar.gz
tar -xfUXo v1.16.3-zos.tar
chtag -tc 819 -R ./libkrb5-zos-1.16.3-zos
chtag -b -R ./libkrb5-zos-1.16.3-zos/lib
```
- Set the following environment variables:
```
export KRB5_HOME=/path/to/libkrb5-zos-1.16.3-zos
export KRB5_CONFIG=/path/to/krb5.conf
```

### Installation

Now you can install `kerberos` with the following:

```bash
npm install kerberos
```

### Testing

Run the test suite using:

```bash
npm test
```

NOTE: The test suite requires an active kerberos deployment, see `test/scripts/travis.sh` to better understand these requirements.

# Documentation

## Classes

<dl>
<dt><a href="#KerberosClient">KerberosClient</a></dt>
<dd></dd>
<dt><a href="#KerberosServer">KerberosServer</a></dt>
<dd></dd>
</dl>

## Functions

<dl>
<dt><a href="#checkPassword">checkPassword(username, password, service, [defaultRealm], [callback])</a> ⇒ <code>Promise</code></dt>
<dd><p>This function provides a simple way to verify that a user name and password
match those normally used for Kerberos authentication.
It does this by checking that the supplied user name and password can be
used to get a ticket for the supplied service.
If the user name does not contain a realm, then the default realm supplied
is used.</p>
<p>For this to work properly the Kerberos must be configured properly on this
machine.
That will likely mean ensuring that the edu.mit.Kerberos preference file
has the correct realms and KDCs listed.</p>
<p>IMPORTANT: This method is vulnerable to KDC spoofing attacks and it should
only be used for testing. Do not use this in any production system - your
security could be compromised if you do.</p>
</dd>
<dt><a href="#principalDetails">principalDetails(service, hostname, [callback])</a> ⇒ <code>Promise</code></dt>
<dd><p>This function returns the service principal for the server given a service type and hostname.</p>
<p>Details are looked up via the <code>/etc/keytab</code> file.</p>
</dd>
<dt><a href="#initializeClient">initializeClient(service, [options], [callback])</a> ⇒ <code>Promise</code></dt>
<dd><p>Initializes a context for client-side authentication with the given service principal.</p>
</dd>
<dt><a href="#initializeServer">initializeServer(service, [callback])</a> ⇒ <code>Promise</code></dt>
<dd><p>Initializes a context for server-side authentication with the given service principal.</p>
</dd>
</dl>

<a name="KerberosClient"></a>

## KerberosClient
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| username | <code>string</code> | The username used for authentication |
| response | <code>string</code> | The last response received during authentication steps |
| responseConf | <code>string</code> | Indicates whether confidentiality was applied or not (GSSAPI only) |
| contextComplete | <code>boolean</code> | Indicates that authentication has successfully completed or not |


* [KerberosClient](#KerberosClient)

    * [.step(challenge, [callback])](#KerberosClient+step)

    * [.wrap(challenge, [options], [callback])](#KerberosClient+wrap)

    * [.unwrap(challenge, [callback])](#KerberosClient+unwrap)


<a name="KerberosClient+step"></a>

### *kerberosClient*.step(challenge, [callback])

| Param | Type | Description |
| --- | --- | --- |
| challenge | <code>string</code> | A string containing the base64-encoded server data (which may be empty for the first step) |
| [callback] | <code>function</code> |  |

Processes a single kerberos client-side step using the supplied server challenge.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="KerberosClient+wrap"></a>

### *kerberosClient*.wrap(challenge, [options], [callback])

| Param | Type | Description |
| --- | --- | --- |
| challenge | <code>string</code> | The response returned after calling `unwrap` |
| [options] | <code>object</code> | Optional settings |
| [options.user] | <code>string</code> | The user to authorize |
| [callback] | <code>function</code> |  |

Perform the client side kerberos wrap step.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="KerberosClient+unwrap"></a>

### *kerberosClient*.unwrap(challenge, [callback])

| Param | Type | Description |
| --- | --- | --- |
| challenge | <code>string</code> | A string containing the base64-encoded server data |
| [callback] | <code>function</code> |  |

Perform the client side kerberos unwrap step

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="KerberosServer"></a>

## KerberosServer
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| username | <code>string</code> | The username used for authentication |
| response | <code>string</code> | The last response received during authentication steps |
| targetName | <code>string</code> | The target used for authentication |
| contextComplete | <code>boolean</code> | Indicates that authentication has successfully completed or not |

<a name="KerberosServer+step"></a>

### *kerberosServer*.step(challenge, [callback])

| Param | Type | Description |
| --- | --- | --- |
| challenge | <code>string</code> | A string containing the base64-encoded client data |
| [callback] | <code>function</code> |  |

Processes a single kerberos server-side step using the supplied client data.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="checkPassword"></a>

## checkPassword(username, password, service, [defaultRealm], [callback])

| Param | Type | Description |
| --- | --- | --- |
| username | <code>string</code> | The Kerberos user name. If no realm is supplied, then the `defaultRealm` will be used. |
| password | <code>string</code> | The password for the user. |
| service | <code>string</code> | The Kerberos service to check access for. |
| [defaultRealm] | <code>string</code> | The default realm to use if one is not supplied in the user argument. |
| [callback] | <code>function</code> |  |

This function provides a simple way to verify that a user name and password
match those normally used for Kerberos authentication.
It does this by checking that the supplied user name and password can be
used to get a ticket for the supplied service.
If the user name does not contain a realm, then the default realm supplied
is used.

For this to work properly the Kerberos must be configured properly on this
machine.
That will likely mean ensuring that the edu.mit.Kerberos preference file
has the correct realms and KDCs listed.

IMPORTANT: This method is vulnerable to KDC spoofing attacks and it should
only be used for testing. Do not use this in any production system - your
security could be compromised if you do.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="principalDetails"></a>

## principalDetails(service, hostname, [callback])

| Param | Type | Description |
| --- | --- | --- |
| service | <code>string</code> | The Kerberos service type for the server. |
| hostname | <code>string</code> | The hostname of the server. |
| [callback] | <code>function</code> |  |

This function returns the service principal for the server given a service type and hostname.

Details are looked up via the `/etc/keytab` file.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="initializeClient"></a>

## initializeClient(service, [options], [callback])

| Param | Type | Description |
| --- | --- | --- |
| service | <code>string</code> | A string containing the service principal in the form 'type@fqdn' (e.g. 'imap@mail.apple.com'). |
| [options] | <code>object</code> | Optional settings |
| [options.principal] | <code>string</code> | Optional string containing the client principal in the form 'user@realm' (e.g. 'jdoe@example.com'). |
| [options.gssFlags] | <code>number</code> | Optional integer used to set GSS flags. (e.g.  GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG will allow for forwarding credentials to the remote host) |
| [options.mechOID] | <code>number</code> | Optional GSS mech OID. Defaults to None (GSS_C_NO_OID). Other possible values are `GSS_MECH_OID_KRB5`, `GSS_MECH_OID_SPNEGO`. |
| [callback] | <code>function</code> |  |

Initializes a context for client-side authentication with the given service principal.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
<a name="initializeServer"></a>

## initializeServer(service, [callback])

| Param | Type | Description |
| --- | --- | --- |
| service | <code>string</code> | A string containing the service principal in the form 'type@fqdn' (e.g. 'imap@mail.apple.com'). |
| [callback] | <code>function</code> |  |

Initializes a context for server-side authentication with the given service principal.

**Returns**: <code>Promise</code> - returns Promise if no callback passed  
