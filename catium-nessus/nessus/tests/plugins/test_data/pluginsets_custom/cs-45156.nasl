if(description)
{
 script_id(999999);
 script_name(english:"CS-45156");
 script_summary(english:"Slow regex execution.");
 script_family(english:"CS-45156");
 script_timeout(5);
}

set_mem_limits(max_alloc_size: 536870912, max_program_size: 836870912);

filename = "big.txt";


pattern = '((^|[^/]+)/(Library|var|etc|home|bin|etc|opt|private|usr)(/([^/<>: ]+/)+)niet353545097.html)|((^|[^/]+)/(Library|var|etc|home|bin|etc|opt|private|usr)(/([^/<>: ]+/)+)niet353545097.shtml)|(([0-9.]+.+) &copy; (19|20)[0-9][0-9] .+IPS, .+Inc)|((^|[^/]+)/(Library|var|etc|home|bin|etc|opt|private|usr)(/([^/<>: ]+/)+)niet1762775976.php5)|(<[^"]*("[^"]*")*[^"]*"" onfocus="alert\\([1-4]?[0-9][0-9]\\))';

f = file_open(name: filename, mode: "r");
data = file_read(fp: f, length: 209715200);
file_close(f);

egrep(pattern: pattern, string: data);
