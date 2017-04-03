MySQLTuner :version - MySQL High Performance Tuning Script
Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner
Maintained by Immanuel Washington (:email) - Licensed under GPL

Important Usage Guidelines:
  To run the script with the default options, run the script without arguments
  Allow MySQL server to run for at least 24-48 hours before trusting suggestions
  Some routines may require root level privileges (script will provide warnings)
  You must provide the remote server's total memory when connecting to other servers

Connection and Authentication
  --host <hostname>       Connect to a remote host to perform tests (default: localhost)
  --socket <socket>       Use a different socket for a local connection
  --port <port>           Port to use for connection (default: 3306)
  --user <username>       Username to use for authentication
  --user-env <envvar>     Name of env variable which contains username to use for authentication
  --pass <password>       Password to use for authentication
  --pass-env <envvar>     Name of env variable which contains password to use for authentication
  --defaults-file <path>  Path to a custom .my.cnf
  --mysqladmin <path>     Path to a custom mysqladmin executable
  --mysqlcmd <path>       Path to a custom mysql executable
  --no-ask                Don't ask password if needed

Performance and Reporting Options
  --skip-size   Don't enumerate tables and their types/sizes (default: on)
    (Recommended for servers with many tables)
  --skip-password         Don't perform checks on user passwords(default: off)
  --check-version         Check for updates to MySQLTuner
  --update-version        Check for updates to MySQLTuner and update when newer version is available
  --force-mem <size>      Amount of RAM installed in megabytes
  --force-swap <size>     Amount of swap memory configured in megabytes
  --password-file <path>  Path to a password file list(one password by line)

Output Options:
  --silent                Don't output anything on screen
  --no-good               Remove OK responses
  --no-bad                Remove negative/suggestion responses
  --no-info               Remove informational responses
  --debug                 Print debug information
  --db-stat               Print database information
  --idx-stat              Print index information
  --sys-stat              Print system information
  --pf-stat               Print Performance schema information
  --banned-ports          Ports banned separated by comma(,)
  --max-port-allowed      Number of ports opened allowed on this hosts
  --cve-file              CVE File for vulnerability checks
  --nocolor               Don't print output in color
  --json                  Print result as JSON string
  --pretty-json           Print result as human readable JSON
  --buffers               Print global and per-thread buffer values
  --output-file <path>    Path to a output txt file
  --report-file <path>    Path to a report txt file
  --template <path>       Path to a template file
  --verbose               Prints out all options (default: no verbose)
