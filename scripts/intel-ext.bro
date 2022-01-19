##! Extends the intel.log with additional fields

module IntelExtend;

# Fields need to be sets since the Intel framework will add fields from each identical
# record found from each intel source
# TODO: Some of these fields are CIF specific but could be used as we find other sources of Intel (e.g. ThreatQ, X-Force)
# But, at this time, sticking with the specific cif_* naming convention until we know more
redef record Intel::Info += {
    description: set[string] &optional &log;
    source: set[string] &optional &log;
    cif_confidence: set[double] &optional &log;
    cif_severity: set[string] &optional &log;
    cif_impact: set[string] &optional &log;
    feed_source: set[string] &optional &log;
    url: set[string] &optional &log;
};

hook Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set [Intel::Item]) : bool &priority=0 
{
    # Enumerate the items in the intel set and add appropriate records
    for ( item in items )
    {
        # Add intel default fields that are not normally logged
        if(item$meta?$desc) {
            if ( ! info?$description ) {
                info$description = set();
            }
            add info$description[item$meta$desc];
        }

        if(item$meta?$url) {
            if ( ! info?$url ) {
                info$url = set();
            }
            add info$url[item$meta$url];
        }

        # Collective Intel Framework specific fields
        if(item$meta?$cif_confidence || item$meta?$cif_impact || item$meta?$cif_severity) {
            if ( ! info?$feed_source ) {
                info$feed_source = set();
            }
            add info$feed_source["cif"];
        }

        if(item$meta?$cif_confidence) {
            if ( ! info?$cif_confidence ) {
                info$cif_confidence = set();
            }
            add info$cif_confidence[item$meta$cif_confidence];
        }

        if(item$meta?$cif_severity) {
            if ( ! info?$cif_severity ) {
                info$cif_severity = set();
            }
            add info$cif_severity[item$meta$cif_severity];
        }

        if(item$meta?$cif_impact) {
            if ( ! info?$cif_impact ) {
                info$cif_impact = set();
            }
            add info$cif_impact[item$meta$cif_severity];
        }

    }
}
