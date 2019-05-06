# encoding: utf-8

include_controls 'pgstigcheck-inspec' do
  control 'V-72857' do
    desc 'The CMS standard for authentication is CMS-approved 
         PKI certificates.

         Authentication based on User ID and Password may be 
         used only when it is not possible to employ a PKI 
         certificate, and requires AO approval.

         In such cases, passwords need to be protected at all 
         times, and encryption is the standard method for 
         protecting passwords during transmission.

         PostgreSQL passwords sent in clear text format across 
         the network are vulnerable to discovery by unauthorized 
         users. Disclosure of passwords may easily lead to 
         unauthorized access to the database.'
  end

  control 'V-72859' do
    desc 'Authentication with a CMS-approved PKI certificate does 
         not necessarily imply authorization to access PostgreSQL. 
         To mitigate the risk of unauthorized access to sensitive 
         information by entities that have been issued certificates 
         by CMS-approved PKIs, all CMS systems, including databases, 
         must be properly configured to implement access control 
         policies.

         Successful authentication must not automatically give an 
         entity access to an asset or security boundary. 
         Authorization procedures and controls must be implemented 
         to ensure each authenticated entity also has a validated 
         and current authorization. Authorization is the process 
         of determining whether an entity, once authenticated, is 
         permitted to access a specific asset. Information systems 
         use access control policies and enforcement mechanisms to 
         implement this requirement.

         Access control policies include identity-based policies, 
         role-based policies, and attribute-based policies. Access 
         enforcement mechanisms include access control lists, 
         access control matrices, and cryptography. These policies 
         and mechanisms must be employed by the application to 
         control access between users (or processes acting on behalf 
         of users) and objects (e.g., devices, files, records, 
         processes, programs, and domains) in the information system.

         This requirement is applicable to access control enforcement   
         applications, a category that includes database management 
         systems. If PostgreSQL does not follow applicable policy when 
         approving access, it may be in conflict with networks or other 
         applications in the information system. This may result in 
         users either gaining or being denied access inappropriately 
         and in conflict with applicable policy.'
  end

  control 'V-72863' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, 
    since the related security control is not applied to this 
    system categorization in CMS ARS 3.1'
  end

  control "V-72883" do
    title "PostgreSQL must enforce discretionary access control policies, as
    defined by the data owner, over defined subjects and objects."
    desc  "Discretionary Access Control (DAC) is based on the notion that
    individual users are \"owners\" of objects and therefore have discretion over
    who should be authorized to access the object and in which mode (e.g., read or
    write). Ownership is usually acquired as a consequence of creating the object
    or via specified ownership assignment. DAC allows the owner to determine who
    will have access to objects they control. An example of DAC includes
    user-controlled table permissions.
    When discretionary access control policies are implemented, subjects are not
    constrained with regard to what actions they can take with information for
    which they have already been granted access. Thus, subjects that have been
    granted access to information are not prevented from passing (i.e., the
    subjects have the discretion to pass) the information to other subjects or
    objects.
    A subject that is constrained in its operation by Mandatory Access Control
    policies is still able to operate under the less rigorous constraints of this
    requirement. Thus, while Mandatory Access Control imposes constraints
    preventing a subject from passing information to another subject operating at
    a different sensitivity level, this requirement permits the subject to pass
    the information to any subject at the same sensitivity level.
    The policy is bounded by the information system boundary. Once the information
    is passed outside of the control of the information system, additional means
    may be required to ensure the constraints remain in effect. While the older,
    more traditional definitions of discretionary access control require i
    dentity-based access control, that limitation is not required for this use of
    discretionary access control."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000328-DB-000301"
    tag "gid": "V-72883"
    tag "rid": "SV-87535r1_rule"
    tag "stig_id": "PGS9-00-002200"
    tag "cci": ["CCI-002165"]
    tag "nist": ["AC-3 (4)", "Rev_4"]
    tag "check": "Review system documentation to identify the required
    discretionary access control (DAC).
    Review the security configuration of the database and PostgreSQL. If
    applicable, review the security configuration of the application(s) using the
    database.
    If the discretionary access control defined in the documentation is not
    implemented in the security configuration, this is a finding.
    If any database objects are found to be owned by users not authorized to own
    database objects, this is a finding.
    To check the ownership of objects in the database, as the database
    administrator, run the following:
    $ sudo su - postgres
    $ psql -c \"\\dn *.*\"
    $ psql -c \"\\dt *.*\"
    $ psql -c \"\\ds *.*\"
    $ psql -c \"\\dv *.*\"
    $ psql -c \"\\df+ *.*\"
    If any role is given privileges to objects it should not have, this is a
    finding."
    tag "fix": "Implement the organization's DAC policy in the security
    configuration of the database and PostgreSQL, and, if applicable, the security
    configuration of the application(s) using the database.
    To GRANT privileges to roles, as the database administrator (shown here as
    \"postgres\"), run statements like the following examples:
    $ sudo su - postgres
    $ psql -c \"CREATE SCHEMA test\"
    $ psql -c \"GRANT CREATE ON SCHEMA test TO bob\"
    $ psql -c \"CREATE TABLE test.test_table(id INT)\"
    $ psql -c \"GRANT SELECT ON TABLE test.test_table TO bob\"
    To REVOKE privileges to roles, as the database administrator (shown here as
    \"postgres\"), run statements like the following examples:
    $ psql -c \"REVOKE SELECT ON TABLE test.test_table FROM bob\"
    $ psql -c \"REVOKE CREATE ON SCHEMA test FROM bob\""

    sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    authorized_owners = PG_SUPERUSERS

    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{PG_DB}';"
    databases_query = sql.query(databases_sql, [PG_DB])
    databases = databases_query.lines
    types = %w(t s v) # tables, sequences views

    databases.each do |database|
      schemas_sql = ''
      functions_sql = ''

      if database == 'postgres'
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
      else
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
      end

      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)
      
      sql_result=sql.query(schemas_sql, [database])

      if sql_result.empty?
        describe 'There are no database schemas' do
          skip 'There are no database schemas'
        end
      end

      if !sql_result.empty?
        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end

      sql_result=sql.query(functions_sql, [database])

      if sql_result.empty?
        describe 'There are no database functions' do
          skip 'There are no database functions'
        end
      end

      if !sql_result.empty?

        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end

      types.each do |type|
        objects_sql = ''

        if database == 'postgres'
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}' "
            "AND n.nspname !~ '^pg_toast';"
        else
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
            "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
            "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
            " AND n.nspname !~ '^pg_toast';"
        end

        sql_result=sql.query(objects_sql, [database])

        if sql_result.empty?
          describe 'There are no database functions' do
            skip 'There are no database functions'
          end
        end

        if !sql_result.empty?

          describe.one do
            describe sql_result do
              its('output') { should eq '' }
            end

            describe sql_result do
              it { should match connection_error_regex }
            end
          end
        end
      end
    end
  end

  control "V-72897" do
    title "Database objects (including but not limited to tables, indexes,
    storage, trigger procedures, functions, links to software external to
    PostgreSQL, etc.) must be owned by database/DBMS principals authorized for
    ownership."
    desc  "Within the database, object ownership implies full privileges to the
    owned object, including the privilege to assign access to the owned objects
    to other subjects. Database functions and procedures can be coded using
    definer's rights. This allows anyone who utilizes the object to perform the
    actions if they were the owner. If not properly managed, this can lead to
    privileged actions being taken by unauthorized individuals.
    Conversely, if critical tables or other objects rely on unauthorized owner
    accounts, these objects may be lost when an account is removed."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000133-DB-000200"
    tag "gid": "V-72897"
    tag "rid": "SV-87549r1_rule"
    tag "stig_id": "PGS9-00-003100"
    tag "cci": ["CCI-001499"]
    tag "nist": ["CM-5 (6)", "Rev_4"]
    tag "check": "Review system documentation to identify accounts authorized to
    own database objects. Review accounts that own objects in the database(s).
    If any database objects are found to be owned by users not authorized to own
    database objects, this is a finding.
    To check the ownership of objects in the database, as the database
    administrator, run the following SQL:
    $ sudo su - postgres
    $ psql -x -c \"\\dn *.*\"
    $ psql -x -c \"\\dt *.*\"
    $ psql -x -c \"\\ds *.*\"
    $ psql -x -c \"\\dv *.*\"
    $ psql -x -c \"\\df+ *.*\"
    If any object is not owned by an authorized role for ownership, this is a
    finding."
    tag "fix": "Assign ownership of authorized objects to authorized object owner
    accounts.
    #### Schema Owner
    To create a schema owned by the user bob, run the following SQL:
    $ sudo su - postgres
    $ psql -c \"CREATE SCHEMA test AUTHORIZATION bob
    To alter the ownership of an existing object to be owned by the user bob,
    run the following SQL:
    $ sudo su - postgres
    $ psql -c \"ALTER SCHEMA test OWNER TO bob\""

    sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    authorized_owners = PG_SUPERUSERS


    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{PG_DB}';"
    databases_query = sql.query(databases_sql, [PG_DB])
    databases = databases_query.lines
    types = %w(t s v) # tables, sequences views

    databases.each do |database|
      schemas_sql = ''
      functions_sql = ''

      if database == 'postgres'
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
      else
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
      end

      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)

      sql_result=sql.query(schemas_sql, [database])

      if sql_result.empty?
        describe 'There are no database schemas' do
          skip 'There are no database schemas'
        end
      end

      if !sql_result.empty?
        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end

      sql_result=sql.query(functions_sql, [database])

      if sql_result.empty?
        describe 'There are no database functions' do
          skip 'There are no database functions'
        end
      end

      if !sql_result.empty?

        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end

      types.each do |type|
        objects_sql = ''

        if database == 'postgres'
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}' "
            "AND n.nspname !~ '^pg_toast';"
        else
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
            "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
            "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
            " AND n.nspname !~ '^pg_toast';"
        end

        sql_result=sql.query(objects_sql, [database])

        if sql_result.empty?
          describe 'There are no database schemas' do
            skip 'There are no database schemas'
          end
        end

        if !sql_result.empty?
          describe.one do
            describe sql_result do
              its('output') { should eq '' }
            end

            describe sql_result do
              it { should match connection_error_regex }
            end
          end
        end
      end
    end
  end

  control "V-72905" do
    title "Execution of software modules (to include functions and trigger
    procedures) with elevated privileges must be restricted to necessary cases
    only."
    desc  "In certain situations, to provide required functionality, PostgreSQL
    needs to execute internal logic (stored procedures, functions, triggers, etc.)
    and/or external code modules with elevated privileges. However, if the
    privileges required for execution are at a higher level than the privileges
    assigned to organizational users invoking the functionality
    applications/programs, those users are indirectly provided with greater
    privileges than assigned by organizations.
    Privilege elevation must be utilized only where necessary and protected
    from misuse.
    This calls for inspection of application source code, which will require
    collaboration with the application developers. It is recognized that in
    many cases, the database administrator (DBA) is organizationally separate
    from the application developers, and may have limited, if any, access to
    source code. Nevertheless, protections of this type are so important to the
    secure operation of databases that they must not be ignored. At a minimum,
    the DBA must attempt to obtain assurances from the development organization
    that this issue has been addressed, and must document what has been discovered."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000342-DB-000302"
    tag "gid": "V-72905"
    tag "rid": "SV-87557r1_rule"
    tag "stig_id": "PGS9-00-003600"
    tag "cci": ["CCI-002233"]
    tag "nist": ["AC-6 (8)", "Rev_4"]
    tag "check": "Functions in PostgreSQL can be created with the SECURITY
    DEFINER option. When SECURITY DEFINER functions are executed by a user, said
    function is run with the privileges of the user who created it.
    To list all functions that have SECURITY DEFINER, as, the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ sudo su - postgres
    $ psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname,
    proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN
    pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;\"
    In the query results, a prosecdef value of \"t\" on a row indicates that that
    function uses privilege elevation.
    If elevation of PostgreSQL privileges is utilized but not documented, this is
    a finding.
    If elevation of PostgreSQL privileges is documented, but not implemented as
    described in the documentation, this is a finding.
    If the privilege-elevation logic can be invoked in ways other than intended,
    or in contexts other than intended, or by subjects/principals other than
    intended, this is a finding."
    tag "fix": "Determine where, when, how, and by what principals/subjects
    elevated privilege is needed.
    To change a SECURITY DEFINER function to SECURITY INVOKER, as the database
    administrator (shown here as \"postgres\"), run the following SQL:\
    $ sudo su - postgres
    $ psql -c \"ALTER FUNCTION <function_name> SECURITY INVOKER;\""

    sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    security_definer_sql = "SELECT nspname, proname, prosecdef "\
      "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "\
      "JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef = 't';"

    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{PG_DB}';"
    databases_query = sql.query(databases_sql, [PG_DB])
    databases = databases_query.lines

    databases.each do |database|
      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)

      sql_result=sql.query(security_definer_sql, [database])

      if sql_result.empty?
        describe 'There are no database functions that were created with the SECURITY
          DEFINER option' do
          skip 'There are no database functions that were created with the SECURITY
          DEFINER option'
        end
      end

      if !sql_result.empty?
        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end
    end
  end

  control 'V-72961' do
    desc 'For completeness of forensic analysis, it is necessary to 
         track who logs on to PostgreSQL.

         Concurrent connections by the same user from multiple 
         workstations may be valid use of the system; or such 
         connections may be due to improper circumvention of the        
         requirement to use the CAC/PIV for authentication; or they may 
         indicate unauthorized account sharing; or they may be because 
         an account has been compromised.

         (If the fact of multiple, concurrent logons by a given user 
         can be reliably reconstructed from the log entries for other 
         events (logons/connections; voluntary and involuntary 
         disconnections), then it is not mandatory to create additional 
         log entries specifically for this.)'
  end

  control 'V-72979' do
    desc 'The CMS standard for authentication is CMS-approved PKI 
         certificates.

         A certificate certification path is the path from the end 
         entity certificate to a trusted root certification authority 
         (CA). Certification path validation is necessary for a relying 
         party to make an informed decision regarding acceptance of an 
         end entity certificate. Certification path validation includes 
         checks such as certificate issuer trust, time validity and 
         revocation status for each certificate in the certification 
         path. Revocation status information for CA and subject 
         certificates in a certification path is commonly provided via 
         certificate revocation lists (CRLs) or online certificate 
         status protocol (OCSP) responses.

         Database Management Systems that do not validate certificates 
         by performing RFC 5280-compliant certification path validation 
         are in danger of accepting certificates that are invalid and/or 
         counterfeit. This could allow unauthorized access to the database.'
  end

  control 'V-72983' do
    title 'PostgreSQL must provide audit record generation capability 
          for CMS-defined auditable events within all DBMS/database 
          components.'
    desc 'Without the capability to generate audit records, it would 
         be difficult to establish, correlate, and investigate the events 
         relating to an incident or identify those responsible for one. 

         Audit records can be generated from various components within 
         PostgreSQL (e.g., process, module). Certain specific application 
         functionalities may be audited as well. The list of audited events 
         is the set of events for which audits are to be generated. This 
         set of events is typically a subset of the list of all events for 
         which the system is capable of generating audit records.

         CMS has defined the list of events for which PostgreSQL will 
         provide an audit record generation capability as the following: 

         (i) Successful and unsuccessful attempts to access, modify, or 
         delete privileges, security objects, security levels, or categories 
         of information (e.g., classification levels);
         (ii) Access actions, such as successful and unsuccessful logon 
         attempts, privileged activities, or other system-level access, 
         starting and ending time for user access to the system, concurrent 
         logons from different workstations, successful and unsuccessful 
         accesses to objects, all program initiations, and all direct 
         access to the information system; and
         (iii) All account creation, modification, disabling, and 
         termination actions.

         Organizations may define additional events requiring continuous 
         or ad hoc auditing.'
    desc 'fix', 'Configure PostgreSQL to generate audit records for at 
         least the CMS minimum set of events.

         Using pgaudit PostgreSQL can be configured to audit these 
         requests. See supplementary content APPENDIX-B for documentation 
         on installing pgaudit.

         To ensure that logging is enabled, review supplementary content 
         APPENDIX-C for instructions on enabling logging.'
  end

  control 'V-72991' do
    title 'PostgreSQL must use CMS-approved cryptography to protect 
    classified sensitive information in accordance with the data owners 
    requirements.'
    desc 'Use of weak or untested encryption algorithms undermines the 
    purposes of utilizing encryption to protect data. The application 
    must implement cryptographic modules adhering to the higher standards 
    approved by the federal government since this provides assurance 
    they have been tested and validated.

    It is the responsibility of the data owner to assess the cryptography 
    requirements in light of applicable federal laws, Executive Orders, 
    directives, policies, regulations, and standards.'
    desc 'check', 'If PostgreSQL is not using CMS-approved cryptography 
    to protect classified sensitive information in accordance with 
    applicable federal laws, Executive Orders, directives, policies, 
    regulations, and standards, this is a finding.

    To check if PostgreSQL is configured to use SSL, as the database 
    administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW ssl"

    If SSL is off, this is a finding.'
    desc 'fix', 'Note: The following instructions use the PGDATA 
    environment variable. See supplementary content APPENDIX-F for 
    instructions on configuring PGDATA.

    To configure PostgreSQL to use SSL, as a database administrator 
    (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameter:

    ssl = on

    Now, as the system administrator, reload the server with the 
    new configuration:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl reload postgresql-9.5

    # INITD SERVER ONLY
    $ sudo service postgresql-9.5 reload

    For more information on configuring PostgreSQL to use SSL, see 
    supplementary content APPENDIX-G.'
  end

  control "V-72999" do

    title "PostgreSQL must separate user functionality (including user interface
    services) from database management functionality."
    desc  "Information system management functionality includes functions necessary to
    administer databases, network components, workstations, or servers and typically
    requires privileged user access.
    The separation of user functionality from information system management
    functionality is either physical or logical and is accomplished by using different
    computers, different central processing units, different instances of the operating
    system, different network addresses, combinations of these methods, or other
    methods, as appropriate.
    An example of this type of separation is observed in web administrative interfaces
    that use separate authentication methods for users of any other information system
    resources.
    This may include isolating the administrative interface on a different domain and
    with additional access controls.
    If administrative functionality or information regarding PostgreSQL management is
    presented on an interface available for users, information on DBMS settings may be
    inadvertently made available to the user."

    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000211-DB-000122"
    tag "gid": "V-72999"
    tag "rid": "SV-87651r1_rule"
    tag "stig_id": "PGS9-00-008500"
    tag "cci": ["CCI-001082"]
    tag "nist": ["SC-2", "Rev_4"]

    tag "check": "Check PostgreSQL settings and vendor documentation to verify that
    administrative functionality is separate from user functionality.
    As the database administrator (shown here as \"postgres\"), list all roles and
    permissions for the database:
    $ sudo su - postgres
    $ psql -c \"\\du\"
    If any non-administrative role has the attribute \"Superuser\", \"Create role\",
    \"Create DB\" or \"Bypass RLS\", this is a finding.
    If administrator and general user functionality are not separated either physically
    or logically, this is a finding."
    tag "fix": "Configure PostgreSQL to separate database administration and general
    user functionality.
    Do not grant superuser, create role, create db or bypass rls role attributes to
    users that do not require it.
    To remove privileges, see the following example:
    ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;"

    privileges = %w(rolcreatedb rolcreaterole rolsuper)
    sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [PG_DB])
    roles = roles_query.lines

    if roles.empty?
      describe 'There are no database roles' do
        skip 'There are no database roles'
      end
    end

    if !roles.empty?

      roles.each do |role|
        unless PG_SUPERUSERS.include?(role)
          privileges.each do |privilege|
            privilege_sql = "SELECT r.#{privilege} FROM pg_catalog.pg_roles r "\
              "WHERE r.rolname = '#{role}';"

            describe sql.query(privilege_sql, [PG_DB]) do
              its('output') { should_not eq 't' }
            end
          end
        end
      end
    end
  end

  control 'V-73015' do
    desc 'The CMS standard for authentication is CMS-approved PKI 
         certificates.
         
         Authentication based on User ID and Password may be used only 
         when it is not possible to employ a PKI certificate, and 
         requires AO approval.

         In such cases, database passwords stored in clear text, using 
         reversible encryption, or using unsalted hashes would be 
         vulnerable to unauthorized disclosure. Database passwords must 
         always be in the form of one-way, salted hashes when stored 
         internally or externally to PostgreSQL.'
  end

  control "V-73017" do
    title "PostgreSQL must enforce access restrictions associated with changes to the
    configuration of PostgreSQL or database(s)."
    desc  "Failure to provide logical access restrictions associated with changes to
    configuration may have significant effects on the overall security of the system.
    When dealing with access restrictions pertaining to change control, it should be
    noted that any changes to the hardware, software, and/or firmware components of the
    information system can potentially have significant effects on the overall security
    of the system.
    Accordingly, only qualified and authorized individuals should be allowed to obtain
    access to system components for the purposes of initiating changes, including
    upgrades and modifications."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000380-DB-000360"
    tag "gid": "V-73017"
    tag "rid": "SV-87669r1_rule"
    tag "stig_id": "PGS9-00-009600"
    tag "cci": ["CCI-001813"]
    tag "nist": ["CM-5 (1)", "Rev_4"]
    tag "check": "To list all the permissions of individual roles, as the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ sudo su - postgres
    $ psql -c \"\\du
    If any role has SUPERUSER that should not, this is a finding.
    Next, list all the permissions of databases and schemas by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"\\l\"
    $ psql -c \"\\dn+\"
    If any database or schema has update (\"W\") or create (\"C\") privileges and should
    not, this is a finding."
    tag "fix": "Configure PostgreSQL to enforce access restrictions associated with
    changes to the configuration of PostgreSQL or database(s).
    Use ALTER ROLE to remove accesses from roles:
    $ psql -c \"ALTER ROLE <role_name> NOSUPERUSER\"
    Use REVOKE to remove privileges from databases and schemas:
    $ psql -c \"REVOKE ALL PRIVILEGES ON <table> FROM <role_name>;"

    sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [PG_DB])
    roles = roles_query.lines

    if roles.empty?
      describe 'There are no database roles' do
        skip 'There are no database roles'
      end
    end

    if !roles.empty?
      roles.each do |role|
        unless PG_SUPERUSERS.include?(role)
          superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
            "WHERE r.rolname = '#{role}';"

          describe sql.query(superuser_sql, [PG_DB]) do
            its('output') { should_not eq 't' }
          end
        end
      end
    end

    authorized_owners = PG_SUPERUSERS
    owners = authorized_owners.join('|')

    database_granted_privileges = 'CTc'
    database_public_privileges = 'c'
    database_acl = "^((((#{owners})=[#{database_granted_privileges}]+|"\
      "=[#{database_public_privileges}]+)\/\\w+,?)+|)\\|"
    database_acl_regex = Regexp.new(database_acl)

    schema_granted_privileges = 'UC'
    schema_public_privileges = 'U'
    schema_acl = "^((((#{owners})=[#{schema_granted_privileges}]+|"\
      "=[#{schema_public_privileges}]+)\/\\w+,?)+|)\\|"
    schema_acl_regex = Regexp.new(schema_acl)

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
    databases_query = sql.query(databases_sql, [PG_DB])
    databases = databases_query.lines

    if databases.empty?
      describe 'There are no postgres databases' do
        skip 'There are no postgres databases'
      end
    end

    if !databases.empty?
      databases.each do |database|
        datacl_sql = "SELECT pg_catalog.array_to_string(datacl, E','), datname "\
          "FROM pg_catalog.pg_database WHERE datname = '#{database}';"

        describe sql.query(datacl_sql, [PG_DB]) do
          its('output') { should match database_acl_regex }
        end

        schemas_sql = "SELECT n.nspname, FROM pg_catalog.pg_namespace n "\
          "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
        schemas_query = sql.query(schemas_query, [database])
        # Handle connection disabled on database
        if schemas_query.methods.include?(:output)
          schemas = schemas_query.lines

            if schemas.empty?
              describe 'There are no database schemas' do
                skip 'There are no database schemas'
              end
            end

            if !schemas.empty?
            schemas.each do |schema|
              nspacl_sql = "SELECT pg_catalog.array_to_string(n.nspacl, E','), "\
                "n.nspname FROM pg_catalog.pg_namespace n "\
                "WHERE n.nspname = '#{schema}';"

              describe sql.query(nspacl_sql) do
                its('output') { should match schema_acl_regex }
              end
            end
          end
        end
      end
    end
  end

  control 'V-73023' do
    title 'The system must provide a warning to appropriate support 
          staff when allocated audit record storage volume reaches 80% 
          of maximum audit record storage capacity.'
    desc 'Organizations are required to use a central log management system, 
         so, under normal conditions, the audit space allocated to 
         PostgreSQL on its own server will not be an issue. However, 
         space will still be required on PostgreSQL server for audit 
         records in transit, and, under abnormal conditions, this could 
         fill up. Since a requirement exists to halt processing upon 
         audit failure, a service outage would result.

         If support personnel are not notified immediately upon storage 
         volume utilization reaching 80%, they are unable to plan for   
         storage capacity expansion. 

         The appropriate support staff include, at a minimum, the ISSO 
         and the DBA/SA.'
    desc 'check', 'Review system configuration.

         If no script/tool is monitoring the partition for the PostgreSQL 
         log directories, this is a finding.

         If appropriate support staff are not notified immediately upon 
         storage volume utilization reaching 80%, this is a finding.'

    desc 'fix', 'Configure the system to notify appropriate support 
         staff immediately upon storage volume utilization reaching 80%.

         PostgreSQL does not monitor storage, however, it is possible to 
         monitor storage with a script.

         ##### Example Monitoring Script

         #!/bin/bash

         PGDATA=/var/lib/psql/9.5/data
         CURRENT=$(df ${PGDATA?} | grep / | awk "{ print $5}" 
                                 | sed "s/%//g")
         THRESHOLD=80

         if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
         mail -s "Disk Space Alert" mail@support.com << EOF
         The data directory volume is almost full. Used: $CURRENT
         %EOF
         fi

         Schedule this script in cron to run around the clock.'
  end

  control 'V-73027' do
    desc 'The CMS standard for authentication of an interactive user 
         is the presentation of a Personal Identity Verification (PIV) 
         Card or other physical token bearing a valid, current, 
         CMS-issued Public Key Infrastructure (PKI) certificate, coupled 
         with a Personal Identification Number (PIN) to be entered by 
         the user at the beginning of each session and whenever 
         reauthentication is required.

         Without reauthentication, users may access resources or perform 
         tasks for which they do not have authorization.

         When applications provide the capability to change security 
         roles or escalate the functional capability of the application, 
         it is critical the user re-authenticate.

         In addition to the reauthentication requirements associated with 
         session locks, organizations may require reauthentication of 
         individuals and/or devices in other situations, including (but 
         not limited to) the following circumstances:

         (i) When authenticators change;
         (ii) When roles change;
         (iii) When security categorized information systems change;
         (iv) When the execution of privileged functions occurs;
         (v) After a fixed period of time; or
         (vi) Periodically.

         Within CMS, the minimum circumstances requiring reauthentication 
         are privilege escalation and role changes.'
  end

  control 'V-73029' do
    desc 'The CMS standard for authentication is CMS-approved PKI 
         certificates. PKI certificate-based authentication is performed 
         by requiring the certificate holder to cryptographically prove 
         possession of the corresponding private key.

         If the private key is stolen, an attacker can use the private 
         key(s) to impersonate the certificate holder. In cases where 
         PostgreSQL-stored private keys are used to authenticate PostgreSQL 
         to the system, clients, loss of the corresponding private keys 
         would allow an attacker to successfully perform undetected 
         man-in-the-middle attacks against PostgreSQL system and its    
         clients.

         Both the holder of a digital certificate and the issuing authority 
         must take careful measures to protect the corresponding private 
         key. Private keys should always be generated and protected in 
         FIPS 140-2 validated cryptographic modules.

         All access to the private key(s) of PostgreSQL must be restricted 
         to authorized and authenticated users. If unauthorized users have 
         access to one or more of PostgreSQL\'s private keys, an attacker 
         could gain access to the key(s) and use them to impersonate the 
         database on the network or otherwise perform unauthorized actions.'
  end

  control 'V-73031' do
    title 'PostgreSQL must only accept end entity certificates issued by 
          CMS PKI or CMS-approved PKI Certification Authorities (CAs) for 
          the establishment of all encrypted sessions.'
    
    desc 'Only CMS-approved external PKIs have been evaluated to ensure 
         that they have security controls and identity vetting procedures 
         in place which are sufficient for CMS systems to rely on the 
         identity asserted in the certificate. PKIs lacking sufficient 
         security controls and identity vetting procedures risk being 
         compromised and issuing certificates that enable adversaries to 
         impersonate legitimate users. 

         The authoritative list of CMS-approved PKIs is published at 
         http://iase.disa.mil/pki-pke/interoperability.

         This requirement focuses on communications protection for 
         PostgreSQL session rather than for the network packet.'

    desc 'fix', 'Revoke trust in any certificates not issued by a 
         CMS-approved certificate authority.

         Configure PostgreSQL to accept only CMS and CMS-approved PKI 
         end-entity certificates.

         To configure PostgreSQL to accept approved CA\'s, see the 
         official PostgreSQL documentation: 
         http://www.postgresql.org/docs/current/static/ssl-tcp.html

         For more information on configuring PostgreSQL to use SSL, 
         see supplementary content APPENDIX-G.'
  end

  control 'V-73037' do
    tag "cci": ['CCI-001184']
    tag "nist": ['SC-23', 'Rev_4']
   end

  control 'V-73045' do
    tag	"cci": ['CCI-001848']
    tag "nist": ['AU-4', 'Rev_4']
  end

  control 'V-73051' do
    describe 'For this CMS ARS 3.1 overlay, this control must be reviewed manually' do 
      skip 'For this CMS ARS 3.1 overlay, this control must be reviewed manually'
    end
  end

  control 'V-73055' do
    desc 'The CMS standard for authentication is CMS-approved PKI 
         certificates. Once a PKI certificate has been validated, it 
         must be mapped to PostgreSQL user account for the authenticated 
         identity to be meaningful to PostgreSQL and useful for 
         authorization decisions.'
  end
end