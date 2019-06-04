Finelame is a language-independent framework for detecting asymmetric DoS attacks.
It leverages operating system visibility across the entire software stack to instrument key resource allocation and negotiation points.
Finelame leverage eBPF, and its current user-space agent is implemented in python used BCC.
[Finelame's paper](url goes here) was published in the proceedings of ATC 2019.

# Dependencies
The system requires the [BCC tools from iovisor](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
We will run using python 3. Dependencies are (some might be missing but you'll find out when running the system):
* python3-bcc
* pyyaml
* numpy
* pandas

# Configuring Finelame
To use the agent, its configuration file must be informed with details about the application you
intend to monitor, and which resource monitor should be used. In addition, the configuration holds
details about the agent's anomaly detection engine.

An example configuration file is given in `fl_cfg.yml`

## Application configuration
Applications are listed under the `applications` object.
Each application object must be given a path to their executable, and a list of monitors
(the _request mappers_). Each monitor is described by an event name, which is the name of
an application function one's which to monitor. the `in_fn_name` takes the name of the eBPF
code that performs the mapping. An accompanying `ret_fn_name` take sthe name of the eBPF code
that undo the mapping when the function returns.
In general, the format of request mappers is always the same, but as they might use different
cues from the application to use the mapping, multiple can be declared for the various traced
functions (our Node.js probes is a good example).

## Resouce monitors
Resource monitors are eBPF programs attached to key allocation function.
Each `resource_monitor` object is configued with an `event` (the name of the function to be
traced), an `in_fn_name` (the name of the eBPF function to attach), a `type` (tracepoint or probe),
and a `side` (kernel or user). User-level monitors must be given a path to their execuble (e.g.
glibc for malloc).

## eBPF program
Simply gives the path to your ebpf code (a single C file should hold it both request mappers and
resource monitors) to the `ebpf_prog` object.

## Anomaly detection engine
The engine is given a `train time`, used to decide when the agent should pull all the data from
the eBPF hash tables, and train K-means over them. K-means is configured with the `model_params`
object, which contains `k` and a list of `features`. We also use a separate list of features,
in the `request_stats` object, to maintain the Finelame's user-space dataframe which we then
use to hold the training set. (The two lists in the configuration file are probably a bit redundant.)

# Running Finelame
Let's use Node.js as an example for using Finelame.

## Starting the agent
Use the `start_finelame` python script. It will start the agent with a path to configuration file, and a label used to name output files. Train time can also be given to this script, for convenience (this will override the value in the configuration file). The agent must be run with sudo rights, as it attaches privileged probes into some kernel functions.
The following example with create an output directory named "nodejs", set the training period to 200 seconds, read configuration from fl_cfg.yml, and label the experiment "test":

`sudo python3 start_finelame.py --out nodejs --train-time 200 fl_cfg.yml test`

## Starting Node.js and sending requests.
Install Node.js. The version we use in the paper is 12.0.0. Changes in Node's source code might result in our requets-mappers being out of date.
You can use the simple URL parsing script `node-express.js`, and run it with `./node node-express.js`. The script listen on port 3001 for http requests, parse their URL, and lookup for the request file in a directory that you can configure in the script. The script also takes specifically crafted requests at the `/redos` url (this is made so such that one can control experiments, but attackers could insert malicious regex in place of an URI).
A simple way to get a realistic set of files is to gather wikipedia pages, generate a list of files, and have an http client go through this list of files and issue a request to Node.js.

## Use output data
By default the agent outputs, as csv, both the training set, the testing set, and the outlier scores of each tested request.
The columns of the training and testing files include the request id, its closest cluster label (at the time of data collection), an `origin\_ts` field (the time where the first resource consumed by the request was recorded), an `completion_ts` field that indicates when the request completed (taken as the time where the last resource consumed was recorded), and an `origin_ip` field indicating the origin of the request. We take the origin IP from the probe measuring the amount of bytes received on a TCP connection.
The score file gives the prediction label for each request, as well as its outlier score with regard
to each of the K clusters

In addition, the agent create files for various informative parameters, including `clusters_[label].csv`, that holds the l1 and the threshold for each of the clusters;
and the `normalization_[label].csv` file which holds the mean and standard deviation for each of the
features.

This repository provides a python notebook (name here) that can be used to parse the files and plot Finelame's monitoring data.

# Creating new request-mappers
- Identify the key functions that process requests in your software
- If this function takes a request ID as a parameter, and that request ID is consistent through execution on the program, use it for a direct mapping with tid
- Else, generate an internal mapping for 2 level indirection.
- Mapping should be done when the request starts processing, and be undone when it is evicted.
- When the mapping is done, the request-mapper should also record the current time, such that the cputime resource monitors, invoked on timer interrupts and context switches, can correctly account for CPU consumption since the very beginning of the request's mapping. The structure holding this time, in our prototype, is (rather intuitively, right?) named "start".

