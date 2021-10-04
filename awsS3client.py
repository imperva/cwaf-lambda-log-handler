import os
import zlib
from time import sleep
import boto3
import logging
import logging.handlers
from splunk_handler import SplunkHandler


def lambda_handler(event, context):
    # Read in the environment and set the splunk logger variables
    host = os.environ['host']
    token = os.environ['token']
    port = int(os.environ['port'])
    index = os.environ['index']
    sourcetype = os.environ['sourcetype']
    verify = str2bool(os.environ['verify'])
    debug = str2bool(os.environ['debug'])
    retry_count = int(os.environ['retry_count'])
    source = os.environ['source']
    retry_backoff = float(os.environ['retry_backoff'])
    timeout = int(os.environ['timeout'])
    flush_interval = float(os.environ['flush_interval'])
    queue_size = int(os.environ['queue_size'])
    compressed = str2bool(os.environ['compressed'])
    key = None
    bucket = None

    #Create a logger
    logger = logging.getLogger("AWS")
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.info("Starting splunk logger.")
    # Instantiate the splunk logger
    splunk_handler = SplunkHandler(host=host, port=port, token=token, index=index, sourcetype=sourcetype, debug=debug,
                                   verify=verify, retry_count=retry_count, source=source, retry_backoff=retry_backoff, allow_overrides=True,
                                   timeout=timeout, flush_interval=flush_interval, queue_size=queue_size, record_format=False)

    # Create the custom logger
    splunk_logger = logging.getLogger("SplunkLogger")
    if debug:
        splunk_logger.setLevel(logging.DEBUG)
    else:
        splunk_logger.setLevel(logging.INFO)
    splunk_logger.addHandler(splunk_handler)

    # Get the information that was passed in from S3 PUT trigger
    for record in event['Records']:
        key = record['s3']['object']['key']
        bucket = record['s3']['bucket']['name']
        logging.debug("Found {} key in {} bucket.".format(key, bucket))
    # We got the file and bucket info, lets go get the object
    logger.debug("Try to get file {} in bucket {}.".format(key, bucket))
    s3_client = boto3.client('s3')

    # Get the object instead of downloading the file
    obj = s3_client.get_object(Bucket=bucket, Key=key)

    # Read in the Body element data, this is the raw file data; S3 Object is a JSON object
    file_content = obj['Body'].read()

    # Split the contents of the file, header info from SIEM data
    file_split_data = file_content.split(b"|==|\n")[1]

    # Decompress the SIEM data
    if compressed:
        uncompressed_file_content = zlib.decompressobj().decompress(file_split_data).decode("utf-8")
    else:
        uncompressed_file_content = file_split_data.decode("utf-8")

    # Send the data to Splunk via HTTP Event Collector
    logger.debug("Send this data to {}.".format(host))
    for msg in uncompressed_file_content.splitlines():
        if msg != '':
            splunk_logger.info(msg, extra={"_time": int(str.split(msg, "start=")[1].split(" ")[0])})
            splunk_handler.log_payload.count()
            if len(splunk_handler.queue) >= queue_size:
                logger.debug("Start Flush")
                splunk_handler.force_flush()
                logger.debug("Finished Flushing - Queue size = {}".format(len(splunk_handler.queue)))
            logger.debug("Queue size = {}".format(len(splunk_handler.queue)))

    logger.debug("Final Queue size = {}".format(len(splunk_handler.queue)))

    # Delete log when done.
    while len(splunk_handler.queue) > 0:
        logger.debug("Waiting - Final Queue size = {}".format(len(splunk_handler.queue)))
        sleep(1)
    s3_client.delete_object(Bucket=bucket, Key=key)
    logger.debug("All done!!")


def str2bool(v):
    if v == "True":
        return True
    else:
        return False


def event_time(msg):
    return int(str.split(msg, "start=")[1].split(" ")[0])