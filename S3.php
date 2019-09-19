<?php

namespace levmorozov\s3;

class S3
{
    private $access_key;
    private $secret_key;
    private $endpoint;
    private $region;

    private $useHttps = false;

    const ACL_PRIVATE = 'private';
    const ACL_PUBLIC_READ = 'public-read';
    const ACL_PUBLIC_READ_WRITE = 'public-read-write';
    const ACL_AUTHENTICATED_READ = 'authenticated-read';

    const STORAGE_CLASS_STANDARD = 'STANDARD';
    const STORAGE_CLASS_RRS = 'REDUCED_REDUNDANCY';
    const STORAGE_CLASS_STANDARD_IA = 'STANDARD_IA';
    const STORAGE_CLASS_COLD = 'COLD';
    const STORAGE_CLASS_NEARLINE = 'NEARLINE';


    public function __construct($access_key, $secret_key, $endpoint = 's3.amazonaws.com', $region = 'us-east-1')
    {
        $this->access_key = $access_key;
        $this->secret_key = $secret_key;
        $this->endpoint = $endpoint;
        $this->region = $region;
    }

    public function putObject($opts)
    {
        $opts = array_replace([
            'Body' => null,
            'SourceFile' => null,
            'Key' => null,
            'Bucket' => null,
            'ACL' => self::ACL_PRIVATE,
            'StorageClass' => self::STORAGE_CLASS_STANDARD
        ], $opts);

        if ($opts['SourceFile']) {

            if (!is_readable($opts['SourceFile'])) {
                throw new \Exception("Unable to open input file " . $opts['SourceFile']);
            }

            $this->file = $opts['SourceFile'];
            clearstatcache(false, $this->file);

            $this->size = filesize($this->file);
        } else {
            $this->data = $opts['Body'];
            $this->size = strlen($this->data);
        }

        $this->bucket = $opts['Bucket'];

        if ($opts['StorageClass'] !== self::STORAGE_CLASS_STANDARD)
            $this->headers['x-amz-storage-class'] = $opts['StorageClass'];

        $this->headers['x-amz-acl'] = $opts['ACL'];

        return $this->request('PUT', $opts['Key']);
    }


    public function getObject($opts)
    {
        $opts = array_replace([
            'Bucket' => null,
            'Key' => null,
            'SaveAs' => null,
        ], $opts);

        $this->bucket = $opts['Bucket'];
        $this->saveAs = null;
        if($opts['SaveAs']) {
            if(!is_resource($opts['SaveAs'])) {
                if(($this->fp = fopen($opts['SaveAs'], 'wb')) === false) {
                    // todo: error
                }
            } else {
                $this->fp = &$opts['SaveAs'];
            }
        }

        return $this->request('GET', $opts['Key']);
    }


    public function getObjectInfo($opts)
    {
        $opts = array_replace([
            'Bucket' => null,
            'Key' => null,
        ], $opts);

        $this->bucket = $opts['Bucket'];

        return $this->request('HEAD', $opts['Key']);
    }

    public function deleteObject($opts)
    {
        $opts = array_replace([
            'Bucket' => null,
            'Key' => null,
        ], $opts);

        $this->bucket = $opts['Bucket'];

        return $this->request('DELETE', $opts['Key']);
    }

    public function getBucket($bucket)
    {
        throw new \Exception("Not implemented yet");
    }

    private $headers = ['Host' => '', 'Date' => '', 'Content-Type' => 'application/octet-stream'];
    private $bucket;
    private $uri;
    private $data;
    private $file;
    private $size;
    private $fp = false;
    private $resource;

    private $response;

    protected function request($method, $uri)
    {
        $this->response = [
            'code' => null,
            'headers' => [],
            'error' => null,
            'body' => null
        ];

        $this->uri = $uri !== '' ? '/' . str_replace('%2F', '/', rawurlencode($uri)) : '/';

        if ($this->bucket !== '') {
            $this->headers['Host'] = $this->bucket . '.' . $this->endpoint;
            $this->resource = '/' . $this->bucket . $this->uri;
        } else {
            $this->headers['Host'] = $this->endpoint;
            $this->resource = $this->uri;
        }

        $url =  ($this->useHttps ? 'https://' : 'http://' ) . ($this->headers['Host'] !== '' ? $this->headers['Host'] : $this->endpoint) . $this->uri;

        // Basic setup
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_USERAGENT, 'S3/php');

        curl_setopt($curl, CURLOPT_URL, $url);

        // Headers
        $httpHeaders = [];

        $this->headers['x-amz-date'] = gmdate('Ymd\THis\Z');

        if(!isset($this->headers['x-amz-content-sha256'])) {
            $this->headers['x-amz-content-sha256'] = ($this->file)
                ? hash_file('sha256', $this->file)
                : hash('sha256', $this->data);
        }

        array_filter($this->headers);

        foreach ($this->headers as $header => $value)
            if (strlen($value) > 0) $httpHeaders[] = $header . ': ' . $value;

        $httpHeaders[] = 'Authorization: ' . $this->getSignatureV4($method);

        curl_setopt($curl, CURLOPT_HTTPHEADER, $httpHeaders);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($curl, CURLOPT_WRITEFUNCTION, [&$this, '__responseWriteCallback']);
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, [&$this, '__responseHeaderCallback']);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT , 2);

        switch ($method) {
            case 'GET':
                break;
            case 'PUT':
                if ($this->fp !== false) {
                    curl_setopt($curl, CURLOPT_PUT, true);
                    curl_setopt($curl, CURLOPT_INFILE, $this->fp);
                    if ($this->size >= 0)
                        curl_setopt($curl, CURLOPT_INFILESIZE, $this->size);
                } elseif ($this->data !== false) {
                    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
                    curl_setopt($curl, CURLOPT_POSTFIELDS, $this->data);
                } else
                    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
                break;
            case 'HEAD':
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'HEAD');
                curl_setopt($curl, CURLOPT_NOBODY, true);
                break;
            case 'DELETE':
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
            default:
                break;
        }

        if (curl_exec($curl)) {
            $content_type = curl_getinfo($curl, CURLINFO_CONTENT_TYPE);

            if ($this->response['code'] > 300 && strpos($content_type, 'application/xml') !== false) {
                $response = simplexml_load_string($this->response['body']);
                if ($response) {
                    $error = array(
                        'code' => (string)$response->Code,
                        'message' => (string)$response->Message,
                    );
                    if (isset($response->Resource)) {
                        $error['resource'] = (string)$response->Resource;
                    }
                    $this->response['error'] = $error;
                }
                unset($this->response['body']);
            }
        } else {
            $this->response['error'] = [
                'code' => curl_errno($curl),
                'message' => curl_error($curl),
                'resource' => $this->resource
            ];
        }

        @curl_close($curl);

        if ($this->fp !== false && is_resource($this->fp))
            fclose($this->fp);

        return $this->response;
    }


    private function getSignatureV4($method)
    {
        $combinedHeaders = [];

        $amzDateStamp = substr($this->headers['x-amz-date'], 0, 8);

        foreach ($this->headers as $k => $v)
            $combinedHeaders[strtolower($k)] = trim($v);

        ksort($combinedHeaders);

        $amzPayload = [$method, $this->uri, ""];

        foreach ($combinedHeaders as $k => $v) {
            $amzPayload[] = $k . ':' . $v;
        }
        // add a blank entry so we end up with an extra line break
        $amzPayload[] = '';

        $amzPayload[] = implode(';', array_keys($combinedHeaders));
        $amzPayload[] = $this->headers['x-amz-content-sha256'];

        $credentialScope = [$amzDateStamp, $this->region, 's3', 'aws4_request'];

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $this->headers['x-amz-date'],
            implode('/', $credentialScope),
            hash('sha256', implode("\n", $amzPayload))
        ]);

        $kSecret = 'AWS4' . $this->secret_key;
        $kDate = hash_hmac('sha256', $amzDateStamp, $kSecret, true);
        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        $kService = hash_hmac('sha256', 's3', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $signature = hash_hmac('sha256', $stringToSign, $kSigning);
        return 'AWS4-HMAC-SHA256' . ' ' . implode(',', array(
                'Credential=' . $this->access_key . '/' . implode('/', $credentialScope),
                'SignedHeaders=' . implode(';', array_keys($combinedHeaders)),
                'Signature=' . $signature,
            ));
    }


    /**
     * CURL write callback
     *
     * @param resource &$curl CURL resource
     * @param string &$data Data
     * @return integer
     */
    private function __responseWriteCallback(&$curl, &$data)
    {
        $this->response['code'] = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        if (in_array($this->response['code'], array(200, 206)) && $this->fp !== false)
            return fwrite($this->fp, $data);
        else
            $this->response['body'] .= $data;

        return strlen($data);
    }


    /**
     * CURL header callback
     *
     * @param resource $curl CURL resource
     * @param string $data Data
     * @return integer
     */
    private function __responseHeaderCallback($curl, $data)
    {
        $headers = explode(':', $data);
        if(count($headers) == 2) {
            list($key, $value) = $headers;
            $this->response['headers'][$key] = trim($value);
        }
        return strlen($data);
    }
}

