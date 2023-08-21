# EC2

## Name

*ec2* - enables serving zone data from AWS EC2 instances metadata.

## Description

This plugin allows to resolve server names into the corresponding IP addresses using AWS EC2 instances metadata.

## Syntax

```
ec2 [ZONES...] {
    endpoint ENDPOINT_URL
    access_key_id ACCESS_KEY_ID
    secret_key SECRET_KEY
    region REGION_NAME
    ttl SECONDS
    reload DURATION
    fallthrough [ZONES...]
}
```

* **ZONES** zones it should be authoritative for. If empty, the zones from the configuration block
   are used.
* `endpoint` specifies the AWS EC2 Endpoint URL.
* `access_key_id` specifies the ACCESS_KEY_ID.
* `secret_key` specifies the SECRET_KEY.
* `region` specifies the AWS region.
* `ttl` change the DNS TTL of the records generated (forward and reverse). The default is 3600 seconds (1 hour).
* `reload` change the period between reload data from OpenStack. A time of zero seconds disables the
  feature. Examples of valid durations: "300ms", "1.5h" or "2h45m". See Go's
  [time](https://godoc.org/time) package. The default is 30 seconds.
* `fallthrough` If zone matches and no record can be generated, pass request to the next plugin.
  If **[ZONES...]** is omitted, then fallthrough happens for all zones for which the plugin
  is authoritative. If specific zones are listed (for example `in-addr.arpa` and `ip6.arpa`), then only
  queries for those zones will be subject to fallthrough.

## Examples

CROC Cloud

```
. {
    ec2 example.net {
        endpoint https://api.cloud.croc.ru
        access_key_id default:USER@DOMAIN
        secret_key SECRET_KEY
        region croc
        ttl 60
        reload 120
    }
    errors
    log
}
```
