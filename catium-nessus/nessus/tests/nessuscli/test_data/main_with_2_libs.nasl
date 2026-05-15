if (description)
{

script_id(999901);
script_version("1.0");

script_name(english:"Test Plugin With Two Libraries");
script_summary(english:"Plugin that includes lib1.inc and lib2.inc");

script_set_attribute(attribute:"synopsis", value: "Test plugin for SCE-4351");
script_set_attribute(attribute:"description", value: "A test plugin that includes two library files");
script_set_attribute(attribute:"see_also", value: "N/A");
script_set_attribute(attribute:"solution", value: "N/A");
script_set_attribute(attribute:"cvss_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
script_set_attribute(attribute:"plugin_publication_date", value:"2026/01/01");
script_set_attribute(attribute:"plugin_modification_date", value:"2026/01/01");
script_end_attributes();
script_category(ACT_GATHER_INFO);
script_family(english:"Fake Plugins");
script_copyright(english:"Test plugin for SCE-4351 automation");
exit(0);
}

include("lib1.inc");
include("lib2.inc");
