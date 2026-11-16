// Default hardware facts for the Desktop page. Replaced at live boot by
// veloguard-hwprobe.service (veloguard-hwprobe --js); this copy only keeps the
// page loadable if that service hasn't run.
.pragma library
var chassis = "unknown";
var laptop = false;
var gpus = "not probed";
var nvidia = false;
var wifi = false;
var bluetooth = false;
var touchpad = false;
var fingerprint = false;
