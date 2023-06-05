# Function to collect input for a specific variable
def collect_variable_input(variable_name):
    return input(f"Enter {variable_name}: ")

# Function to display collected information
def display_information():
    print("\nCollected Information:")
    for variable in collected_variables:
        print(f"{variable}: {globals()[variable]}")
    print(f"isisID: {isisID}")
    #print(f"ptpFD: {ptpFD}")
    #print(f"ptpFPS: {ptpFPS}")


# Function to format Loop IP into IS-IS ID
def format_isis(loopIP): 
    # Split the IP address into octets
    octets = loopIP.split(".")

    # Format each octet to contain 3 digits, pad with zeros if needed
    formatted_octets = [f"{int(octet):03d}" for octet in octets]

    # Remove decimals from each octet
    stripped_octets = [octet.replace(".", "") for octet in formatted_octets]

    # Join the stripped octets with no separators
    isisID = "".join(stripped_octets)

    # Insert a decimal point every 4 digits
    isisID = ".".join([isisID[i:i+4] for i in range(0, len(isisID), 4)])

    # Lead the formatted IP with "49.0001." and trail with ".00"
    isisID = "49.0001." + isisID + ".00"

    return isisID

# Function to check confirmation and allow correction
def check_confirmation():
    confirmation = input("\nAre the collected information correct? (y/n): ")
    while confirmation.lower() != "y":
        variable_to_correct = input("Which prompt would you like to correct? Enter the prompt: ")
        if variable_to_correct not in collected_variables:
            print("Invalid Variable. Please try again.")
            continue
        corrected_input = collect_variable_input(variable_to_correct)
        globals()[variable_to_correct] = corrected_input  # Update the variable with corrected input
        display_information()
        confirmation = input("\nAre the collected information correct now? (y/n): ")

# Define the variables to collect
collected_variables = [
    "sysName", "sysDesc", "sysLoc", "loopIP", "loopName",
    "ptpIP", "ptpMask", "ptpTag", "ptpPort"
]

# Collect initial input
for variable in collected_variables:
    globals()[variable] = collect_variable_input(variable)

# Format ISIS ID
isisID = format_isis(ptpIP)

# Generate ptpFPS
#ptpFPS = f"fps_VLAN-{ptpTag}_{ptpPort}"

#Generate ptpName
#ptpNameholder = ptpName
#ptpName = f"{ptpNameholder}_p{ptpPort}"

#Generate ptpFD
#ptpFD = f"FD_{ptpNameholder}_{ptpPort}"

# Display the collected information
display_information()

# Request confirmation and allow correction
check_confirmation()

# Proceed with further actions
print("Processing further actions...")

# Export collected information to a text file
filename = f"{sysName}conf.txt"



# Display the collected information
display_information()

# Request confirmation and allow correction
check_confirmation()

# Proceed with further actions
print("Processing further actions...")

# File.write section
filename = f"{sysName}conf.txt"


with open(filename, "w") as file:
    file.write("#Initial setup boiler plate\n")
    file.write("#System information\n")
    file.write("#Set the hostname, description and location\n\n")

    file.write(f"system config hostname {sysName} description \"{sysDesc}\" location \"{sysLoc}\"\n\n")

    file.write("#Timing information\n")
    file.write("#Set ntp for time sync\n\n")

    file.write("system ntp mode polling polling-interval-min 16 polling-interval-max 16\n")
    file.write("system ntp associations remote-ntp-server server-entry '10.255.3.10'\n")
    file.write("return\n")
    file.write("config\n")
    file.write("system ntp associations remote-ntp-server server-entry '10.0.20.27'\n")
    file.write("return\n")
    file.write("config\n")
    file.write("system ntp associations remote-ntp-server server-entry '10.0.20.26'\n\n")
    file.write("return\n")
    file.write("config\n")
    file.write("#Enable licensing server\n")
    file.write("#Will be reachable from the provisioning network, dhcp range on mgmtbr0\n\n")
    file.write("license-management-config license-server-config '10.255.5.8' server-port 7072 protocol http refresh-time 72\n")

    ###User Config###
    file.write("\n")
    file.write("#Authentication Settings\n")
    file.write("#SAOS 10 must have an admin user and a diag user, and NACM needs updated\n")
    file.write("system aaa authentication users user 'windwave' config username \"windwave\" password-hashed \"$6$axkXdmkylEagXfwi$8eNRaL9QCVyfSQF5mLdChtW4dG3Mwz6v91zt/332QwyoGl2obZqYhLwh4tQU2OY84Y6ulwn0pF7ID9vdgw3/01\" role \"SYSTEM_ROLE_USER\"\n")
    file.write("system aaa authentication users user 'windiag' config username \"windiag\" password-hashed \"$6$DlkDwQPIifzw/CbX$WadyJ1L7rWbXzm.WNbTnntauj69GBmD2ENUwIFgE6LRo0JPkORvNqaLxrzJMrLOUMGNg04IU9Jlswa1P5ldOx/\" role \"SYSTEM_ROLE_DIAG\"\n")
    file.write("nacm groups group 'super' user-name \"user\" \"diag\" \"windwave\" \"windiag\"\n")
    file.write("\n")
    file.write("#############################################################################\n")
    file.write("######## DON'T PASTE PAST HERE UNTIL WINDWAVE USERS HAVE BEEN TESTED ########\n")
    file.write("#############################################################################\n")
    file.write("######### Test access for each above user then delete default users #########\n")
    file.write("#############################################################################\n")
    file.write("\n")
    file.write("no system aaa authentication users user diag\n")
    file.write("no system aaa authentication users user user\n")

    ### NACM Configuration ###
    file.write("\n")
    file.write("#NACM Configuration\n")
    file.write("nacm enable-nacm true\n\n")
    file.write("#Confirm the following groups\n\n")
    file.write("nacm rule-list 'super-acl' group \"super\"\n")
    file.write("nacm rule-list 'super-acl' rule 'permit-all' action permit\n")
    file.write("nacm rule-list 'read-exec' group \"limited\" \"admin\" \"super\"\n")
    file.write("nacm rule-list 'read-exec' rule 'get-permit' module-name \"ietf-netconf\" rpc-name \"get\" access-operations \"exec\" action permit\n")
    file.write("nacm rule-list 'read-exec' rule 'get-config-permit' module-name \"ietf-netconf\" rpc-name \"get-config\" access-operations \"exec\" action permit\n")
    file.write("nacm rule-list 'read-exec' rule 'get-schema-permit' module-name \"ietf-netconf-monitoring\" rpc-name \"get-schema\" access-operations \"exec\" action permit\n")
    file.write("nacm rule-list 'read-exec' rule 'get-bulk-permit' rpc-name \"get-bulk\" access-operations \"exec\" action permit\n")
    file.write("nacm rule-list 'sec-exec-deny' group \"*\"\n")
    file.write("nacm rule-list 'sec-exec-deny' rule 'unlock-user-account' rpc-name \"unlock-user-account\" access-operations \"exec\" action deny\n")
    file.write("nacm rule-list 'admin-acl' group \"admin\"\n")
    file.write("nacm rule-list 'admin-acl' rule 'aaa-write-deny' path \"/oc-sys:system/aaa/authentication\" access-operations \"create update delete\" action deny \n")
    file.write("nacm rule-list 'admin-acl' rule 'aaa-exec-deny' module-name \"ciena-openconfig-aaa\" access-operations \"exec\" action deny \n")
    file.write("nacm rule-list 'admin-acl' rule 'nacm-all-deny' module-name \"ietf-netconf-acm\" action deny \n")
    file.write("nacm rule-list 'admin-acl' rule 'all-permit' action permit \n")
    file.write("nacm rule-list 'ntp-acl' group \"super\" \"admin\" \n")
    file.write("nacm rule-list 'ntp-acl' rule 'ntp-permit' module-name \"ciena-ntp\" action permit \n")
    file.write("nacm rule-list 'read-limited' group \"limited\" \n")
    file.write("nacm rule-list 'read-limited' rule 'exec-deny' access-operations \"exec\" action deny \n")
    file.write("nacm rule-list 'read-limited' rule 'aaa-read-deny' module-name \"openconfig-system\" path \"/oc-sys:system/aaa\" action deny \n")


    #SNMP Configuration
    file.write("\n")
    file.write("#SNMP Configuration\n")
    file.write("snmp community 'windro' text-name \"windro\" security-name \"windro\"\n")
    file.write("snmp vacm group 'WINDRO' member 'windro' security-model v2c\n")
    file.write("snmp vacm group 'WINDRO' access '' 'v2c' 'no-auth-no-priv' read-view \"WINDRO\" notify-view \"WINDRO\"\n")
    file.write("snmp vacm view 'WINDRO' include \"*\"\n")
    file.write("snmp vacm view 'WINDRO' exclude \"private\"\n")

    ###Forwaring Domain##
    file.write("\n")
    file.write("#Forwarding Domain, Flow Point\n\n")
    file.write(f"fds fd 'FD_MPLS_{ptpPort}' mode vpls vlan-id {ptpTag}\n")
    file.write(f"fds fd 'FD_MPLS_{ptpPort}' initiate-l2-transform vlan-stack '1' push-pcp map push-vid {ptpTag}\n")

    ###Classifiers###
    file.write("\n")
    file.write("#Classifier\n")
    file.write(f"classifiers classifier 'VLAN-{ptpTag}' filter-entry 'classifier:vtag-stack' vtags '1' vlan-id {ptpTag}\n")

    ###OC-IF, config for ptp & loop, set MTU
    file.write("\n")
    file.write("###OC-IF, config for ptp & loop, set MTU\n")
    file.write(f"oc-if:interfaces interface 'mgmtbr0' config name \"mgmtbr0\" mtu 1500 description \"bridge interface for out of band management port/local management interface\" role cn-if:management type system\n")
    file.write(f"oc-if:interfaces interface '1' config name \"1\" mtu 9216 description \"1\" auto-negotiation true flow-control off port-speed 1Gb ptp-id \"1\" type ettp\n")
    file.write(f"oc-if:interfaces interface '2' config name \"2\" mtu 9216 description \"2\" auto-negotiation true flow-control off port-speed 1Gb ptp-id \"2\" type ettp\n")
    file.write(f"oc-if:interfaces interface '3' config name \"3\" mtu 9216 description \"3\" auto-negotiation true flow-control off port-speed 1Gb ptp-id \"3\" type ettp\n")
    file.write(f"oc-if:interfaces interface '4' config name \"4\" mtu 9216 description \"4\" auto-negotiation true flow-control off port-speed 1Gb ptp-id \"4\" type ettp\n")
    file.write(f"oc-if:interfaces interface '5' config name \"5\" mtu 9216 description \"5\" auto-negotiation true flow-control off port-speed auto ptp-id \"5\" type ettp\n")
    file.write(f"oc-if:interfaces interface '6' config name \"6\" mtu 9216 description \"6\" auto-negotiation true flow-control off port-speed auto ptp-id \"6\" type ettp\n")
    file.write(f"oc-if:interfaces interface '7' config name \"7\" mtu 9216 description \"7\" auto-negotiation true flow-control off port-speed auto ptp-id \"7\" type ettp\n")
    file.write(f"oc-if:interfaces interface '8' config name \"8\" mtu 9216 description \"8\" auto-negotiation true flow-control off port-speed auto ptp-id \"8\" type ettp\n")
    file.write(f"oc-if:interfaces interface 'remote' config name \"remote\" mtu 9000 description \"in band remote management interface\" role cn-if:management type ip underlay-binding config fd \"remote-fd\"\n")
    file.write(f"oc-if:interfaces interface '{loopName}' config name \"{loopName}\" mtu 9000 type loopback\n")
    file.write(f"oc-if:interfaces interface '{loopName}' ipv4 addresses address '{loopIP}' config ip \"{loopIP}\" prefix-length 32\n")
    file.write(f"oc-if:interfaces interface 'mpls_p8' config name \"mpls_p{ptpPort}\" mtu 9000 type ip underlay-binding config fd \"FD_MPLS_{ptpPort}\"\n")
    file.write(f"oc-if:interfaces interface 'mpls_p8' ipv4 addresses address '{ptpIP}' config ip \"{ptpIP}\" prefix-length {ptpMask}\n")

    ###Logical Ports set MTU###
    file.write("\n")
    file.write("#Logical ports, Set MTU\n")
    file.write("logical-ports logical-port '1' binding \"1\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"1\"\n")
    file.write("logical-ports logical-port '2' binding \"2\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"2\"\n")
    file.write("logical-ports logical-port '3' binding \"3\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"3\"\n")
    file.write("logical-ports logical-port '4' binding \"4\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"4\"\n")
    file.write("logical-ports logical-port '5' binding \"5\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"5\"\n")
    file.write("logical-ports logical-port '6' binding \"6\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"6\"\n")
    file.write("logical-ports logical-port '7' binding \"7\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"7\"\n")
    file.write("logical-ports logical-port '8' binding \"8\" mtu 9216 frame-to-cos-map-policy outer-tag frame-to-cos-map \"default-f2c\" cos-to-frame-map \"default-c2f\" description \"8\"\n")

    ### Flow Point###
    file.write("\n")
    file.write("### Flow Point###\n")
    file.write(f"fps fp 'fp_MPLS-{ptpTag}_{ptpPort}' fd-name \"FD_MPLS_{ptpPort}\" logical-port \"{ptpPort}\" mtu-size 9216 stats-collection on classifier-list \"VLAN-{ptpTag}\"\n")



    ### ISIS Routing, LDP, & MPLS ###
    file.write("\n")
    file.write("#IS-IS Routing\n")
    file.write(f"isis instance 'WWC' dynamic-hostname true net {isisID}\n")
    file.write("isis instance 'WWC' level-1\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("isis instance 'WWC' level-2\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("isis instance 'WWC' proto-ipv4 redistribute protocol 'static'\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("isis instance 'WWC' proto-ipv4 redistribute protocol 'connected'\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write(f"isis instance 'WWC' interfaces interface {loopName} level-2\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write(f"isis instance 'WWC' interfaces interface mpls_p{ptpPort} level-type level-1\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("exit\n")
    file.write("isis instance 'WWC' segment-routing enabled true\n")
    file.write("isis instance 'WWC' segment-routing bindings\n")
    file.write(f"ldp instance 'default' lsr-id {loopIP} pw-status-tlv true\n")
    file.write(f"ldp instance 'default' interfaces interface mpls_p{ptpPort} enable-ipv4 true\n")
    file.write(f"ldp instance 'default' interfaces interface {loopName} enable-ipv4 true\n")
    file.write(f"mpls interfaces interface mpls_p{ptpPort} label-switching true\n")
    ## Cleanup
    file.write("#############################################################################\n")
    file.write("############################### CLEANUP TASKS ###############################\n")
    file.write("#############################################################################\n")
    file.write("############### Logical ports and oc-ints  get an mtr of 9216 ###############\n")
    file.write("#################### confirm removal of defaults users. #####################\n")
    file.write("####################### confirm licenses assigned ###########################\n")
    file.write("########## Disable ipv4 and ipv6 dhcp clients on remote and mgmtbr0 #########\n")
    file.write("############## remove remote-fd flowpoints from all interfaces. #############\n")
    file.write("################# pre-enroll device in MCP and update netdot. ###############\n")
    file.write("#############################################################################\n")
    #Remove FPs
    file.write("no fps fp 'remote-fp1'\n")
    file.write("no fps fp 'remote-fp2'\n")
    file.write("no fps fp 'remote-fp3'\n")
    file.write("no fps fp 'remote-fp4'\n")
    file.write("no fps fp 'remote-fp5'\n")
    file.write("no fps fp 'remote-fp6'\n")
    file.write("no fps fp 'remote-fp7'\n")
    file.write("no fps fp 'remote-fp8'\n")
    #Disable DHCP 
    file.write("dhcp-client client 'mgmtbr0' admin-enable false\n")
    file.write("dhcp-client client 'remote' admin-enable false\n")
    file.write("dhcpv6-client client 'remote' admin-enable false\n")
    