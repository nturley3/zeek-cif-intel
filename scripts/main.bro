##! Module for handling CIF intel extensions to the Intel framework
@load base/frameworks/intel

module IntelExtend;

## These are some fields to add extended compatibility between Zeek and the
## Collective Intelligence Framework.
redef record Intel::MetaData += {
	## Maps to the Impact field in the Collective Intelligence Framework.
	cif_impact:     string &optional;
	## Maps to the Severity field in the Collective Intelligence Framework.
	cif_severity:   string &optional;
	## Maps to the Confidence field in the Collective Intelligence Framework.
	cif_confidence: double &optional;
};
