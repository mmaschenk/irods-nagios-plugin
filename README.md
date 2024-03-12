# irods-nagios-plugin

This script can be used by a [nagios server](https://www.nagios.org/) to test the validity and lifetime of an ssl certificate at that server (roughly equivalent to the `check_http --ssl` check)

## installation

Create a virtual python environment for the script and install the requirements:

```shell
% python -m venv .venv
% . .venv/bin/activate
% pip install -r requirements.txt
```

Always run the script using this virtual environment

## nagios config

Add the following command definition to your nagios setup (supposing you cloned this repo to /opt/irods-nagios-plugin and used the above commands for the virtualenv):

```
define command {
    command_name    check-irods-certificate
    command_line    /opt/irods-nagios-plugin/.venv/bin/python /opt/irods-nagios-plugin/check_irods_certificate.py $HOSTADDRESS$
}
```

You can now check your certificate for any given host this way:
```
define service {
      service_description       iRods certificate check
      check_command             check-irods-certificate
      host_name                 <name of your irods server>
}
```
