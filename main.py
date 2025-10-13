import argparse
import binascii
import json
import base64
import logging

import requests

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

logger = logging.getLogger(__name__)

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    url = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=" + str(log_index)
    try: 
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        if r.status_code == 400:
            raise ValueError("Error: The content supplied to the server was invalid.")
        if r.status_code == 404:
            logger.error("log entry not found.")
            raise
        else:
            raise RuntimeError(f"Error: HTTP error {err}, status code: {r.status_code}")
    
    log_entry_json = r.json()
    uuid = next(iter(log_entry_json.keys()))
    if debug:
        logger.debug("UUID: %s", uuid)
        logger.debug("Log entry: %s", log_entry_json)
    
    return uuid, log_entry_json

def get_log_entry_body_b64(log_index, debug=False):
    uuid, log_entry_json = get_log_entry(log_index)
    body_b64 = log_entry_json[uuid]["body"]

    if debug:
        logger.debug("Base64 body:\n%s", body_b64)

    return body_b64


def get_verification_proof(log_index, debug=False):
    uuid, log_entry_json = get_log_entry(log_index)
    inclusion_proof = log_entry_json[uuid]["verification"]["inclusionProof"]
    if debug:
        logger.debug("Inclusion proof: %s", inclusion_proof)

    return inclusion_proof

def inclusion(log_index, artifact_filepath, debug=False):
    body_b64 = get_log_entry_body_b64(log_index, debug)
    
    # decode body > certificate (.pem format)
    try:
        body_bytes = base64.b64decode(body_b64)
        body_str = body_bytes.decode("utf-8")
        body_json = json.loads(body_str)
    except json.JSONDecodeError as err:
        logger.debug(f"Error: decoding log entry response body failed: {err}")
        raise
    except UnicodeDecodeError as err:
        logger.debug(f"Error decoding body bytes using utf-8: {err}")
        raise
    except binascii.Error as err:
        logger.debug(f"Error: Invalid argument supplied to b64decode: {err}")
        raise

    if debug:   
        logger.debug("Decoded body: %s", body_str)

    # extract signature and pubkey
    signature_content = body_json["spec"]["signature"]["content"]
    public_key_content = body_json["spec"]["signature"]["publicKey"]["content"]

    if debug:
        logger.debug("Signature:\n%s", signature_content)
        logger.debug("PublicKey:\n%s", public_key_content)

    # decode signature
    try: 
        sig_bytes = base64.b64decode(signature_content)
    except binascii.Error as err:
        logger.error(f"Error: Invalid argument supplied to b64decode. {err}")
        raise

    # decode pubkey content one more time
    try:
        cert_bytes = base64.b64decode(public_key_content)
    except binascii.Error as err:
        logger.error(f"Error: Invalid argument supplied to b64decode. {err}")
        raise
    
    try:
        cert_str = cert_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        logger.error("Error decoding certificate bytes using utf-8: %s", err)
        raise
    if debug:
        logger.debug("Decoded pubKey Content:\n%s", cert_str)

    # extract pubkey from cert
    pubkey_bytes = extract_public_key(cert_bytes)
    try:
        pubkey_str = pubkey_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        logger.error("Error decoding pubkey_bytes using utf-8: %s", err)
        raise
    if debug: 
        logger.debug("pubkey extracted:\n%s", pubkey_str)

    if verify_artifact_signature(sig_bytes, pubkey_bytes, artifact_filepath):
        logger.debug("Signature is valid.")

    inclusion_proof = get_verification_proof(log_index, debug)
    leaf_hash = compute_leaf_hash(body_b64)
    verify_inclusion(DefaultHasher, inclusion_proof["logIndex"], inclusion_proof["treeSize"], leaf_hash, inclusion_proof["hashes"], inclusion_proof["rootHash"], debug)
    
    return

def get_latest_checkpoint(debug=False):
    url = "https://rekor.sigstore.dev/api/v1/log"
    r = requests.get(url, timeout=5)
    return r.json()

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint["treeSize"]:
        raise SystemExit("Error: required argument --tree-size not supplied")
    if not prev_checkpoint["rootHash"]:
        raise SystemExit("Error: required argument --root-hash not supplied")
    
    latest_checkpoint = get_latest_checkpoint()
    proof_json = get_proof(prev_checkpoint["treeSize"], latest_checkpoint["treeSize"], debug)
    proof_hashes = proof_json["hashes"]
    root1 = prev_checkpoint["rootHash"]
    root2 = latest_checkpoint["rootHash"]

    if debug:
        logger.debug("Prev Checkpoint")
        logger.debug("treeSize: %s", prev_checkpoint["treeSize"])
        logger.debug("rootHash: %s", prev_checkpoint["rootHash"])
        logger.debug("rootHash: %s", root1)

        logger.debug("Latest Checkpoint")
        logger.debug("treesize: %s", latest_checkpoint["treeSize"])
        logger.debug("rootHash: %s", latest_checkpoint["rootHash"])
        logger.debug("rootHash: %s", root2)

    verify_consistency(DefaultHasher, int(prev_checkpoint["treeSize"]), int(latest_checkpoint["treeSize"]), proof_hashes, root1, root2)
    return

def get_proof(firstTreeSize, lastTreeSize, treeID=None, debug=False):
    url = "https://rekor.sigstore.dev/api/v1/log/proof?firstSize=" + str(firstTreeSize) + "&lastSize=" + str(lastTreeSize) #+ "&treeID=" + str(treeID)
    
    try: 
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        if r.status_code == 400:
            raise ValueError("Error: The content supplied to the server was invalid.")
        else:
            raise RuntimeError(f"Error: HTTP error {err}, status code: {r.status_code}")

    response_json = r.json()
    if debug:
        logger.debug("successfully fetched proof")
    return response_json

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        logging.basicConfig(level=logging.DEBUG)
        logger.debug("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            logger.error("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            logger.error("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            logger.error("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
