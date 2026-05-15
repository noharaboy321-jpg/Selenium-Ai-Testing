if (description)
{
  script_id(900001);
  script_version("1.5");
  script_name(english:"Paul's Test Script");
  script_summary(english:"Adds an info vuln.");
  script_set_attribute(
    attribute:"synopsis",
    value: "Adds an info vuln.."
  );
  script_set_attribute(
    attribute:"description",
    value: "Hello there."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"Free");
  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22, "nessus/product/agent");
  exit(0);
}
security_note(port: 0, extra: 'There is nothing to see here, VERSION 2.');