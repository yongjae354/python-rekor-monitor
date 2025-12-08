[![Build Status](https://github.com/yongjae354/python-rekor-monitor/actions/workflows/cd.yml/badge.svg)](https://github.com/yongjae354/python-rekor-monitor/actions/workflows/cd.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yongjae354/python-rekor-monitor/badge)](https://scorecard.dev/viewer/?uri=github.com/yongjae354/python-rekor-monitor)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11582/badge)](https://www.bestpractices.dev/projects/11582)

# Python Rekor Monitor

This is a python monitor for Sigstore's transparency log, [Rekor](https://docs.sigstore.dev/logging/overview/). This project was developed as part of NYU's Software Supply Chain Security class.

## Installation & Requirements

You may either run `git clone` on this repository or download the latest release in [Releases](https://github.com/yongjae354/python-rekor-monitor/releases).

Please use `pip install -r requirements.txt` to install the dependencies on `requirements.txt`.

The python version used for this project is 3.13.2. Older versions may still work but might cause some issues.

## Usage

This program performs 3 main functions.
1. Fetches the latest checkpoint on the Rekor transparency log 
2. Verifies an inclusion of an entry to the transparency log.
3. Verifies the integrity of transparency log at any point of time.

First, to create an entry in the Rekor log, you must sign an artifact using Sigstore Cosign. 
1. Create an artifact file that you wish to sign.
2. [Install sigstore Cosign.](https://docs.sigstore.dev/cosign/system_config/installation/)
3. Sign your artifact using sigstore. You may do this by running `cosign sign-blob <your-artifact> --bundle <your-artifact.bundle>`
More documentation on cosign can be found here: https://docs.sigstore.dev/cosign/signing/signing_with_blobs/

To skip this step, you may alternatively use the `artifact.md` and [`artifact.bundle`](https://github.com/yongjae354/python-rekor-monitor/blob/main/artifact.bundle) files for the next steps.

### Fetching the latest checkpoint
`python main.py --checkpoint`

### Verifying inclusion for your entry
```shell
python main.py --inclusion <log-index> --artifact <your-artifact>
```
This command verifies the inclusion of your log entry. The log index can be found in your bundle file created by Cosign.

### Verifying consistency of the Rekor log
```shell
python main.py --consistency --tree-id <tree-id> --tree-size <tree-size> --root-hash <root-hash>
```

This command verifies that the checkpoint you provide is consistent with the latest checkpoint. The tree-id, tree-size and root-hash fields can be found in any checkpoint of the log, fetched by `--checkpoint`.

## Acknowledgements

The program is built on top of starter code from this template: https://github.com/mayank-ramnani/python-rekor-monitor-template
