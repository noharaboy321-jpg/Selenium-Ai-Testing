if (description)
{

script_id(942018);
script_version("1.0");

script_name(english:"Fake Plugin to cause some scan errors");
script_summary(english:"summary");

script_set_attribute(attribute:"synopsis", value: "synopsis stuff");
script_set_attribute(attribute:"description", value: "description stuff");
script_set_attribute(attribute:"see_also", value: "see_also stuff");
script_set_attribute(attribute:"solution", value: "solution stuff");
script_set_attribute(attribute:"cvss_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/28");
script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"agent", value:"all");
script_end_attributes();
script_category(ACT_GATHER_INFO);
script_family(english:"Fake Plugins");
script_copyright(english:"This script is just thrown together by an engineer trying to cause some scan errors");
exit(0);
}


report_error(severity:1, title:"Scan Error 1", message:"This is the first scan error.");
report_error(title:'Scan Error 4', message:'This error should have severity 1');
report_error_ex(title:'Scan Error 5', message:'Scan error 5 sets nothing in options', options:{});
report_error_ex(title:'Scan Error 6', message:'Scan error 6 sets code = SCAN_ERROR_PLUGIN_GENERIC + 1 (109000 + 1 = 109001)',
    options:{code:SCAN_ERROR_PLUGIN_GENERIC+1});
report_error_ex(title:'Scan Error 7', message:'Scan error 7 sets type = not_a_real_plugin', options:{type:'not_a_real_plugin'});
report_error_ex(title:'Scan Error 8', message:'Scan error 8 sets type = not_a_real_plugin AND code = SCAN_ERROR_PLUGIN_GENERIC + 1',
    options:{code:SCAN_ERROR_PLUGIN_GENERIC+1, type:'not_a_real_plugin'});
report_error_ex(title:'Scan Error 9', message:'Scan error 9 should try to set a non-string as the type, and get the default value instead',
    options:{type:99});
