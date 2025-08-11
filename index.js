const core = require('@actions/core');
const axios = require('axios');
const qs = require('qs');
const fs = require('fs');
const path = require('path');
const { DefaultArtifactClient } = require('@actions/artifact');

const createScanRequestEndpoint = '/api/1.0/scans/CreateFromPluginScanRequest';
const scanStatusPath = '/scans/status/';
const scanStatusEndpoint = '/api/1.0/scans/status/';
const scanInfoEndpoint = '/api/1.0/scans/ScanInfoForPlugin';

const scanTypes = {
  EMPTY: '',
  INCREMENTAL: 'Incremental',
  PRIMARY: 'FullWithPrimaryProfile',
  SELECTED: 'FullWithSelectedProfile',
}

const VULNERABILITY_LEVELS = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  NONE: '',
}

const SEVERITY_LEVELS = {
  CRITICAL: 'Critical',
  HIGH: 'Critical,High',
  MEDIUM: 'Critical,High,Medium',
  LOW: 'Critical,High,Medium,Low',
  BEST_PRACTICE: 'Critical,High,Medium,Low,Best Practice',
  NONE: 'DoNotFail',
}

const requestType = {
  GET: 'GET',
  POST: 'POST',
}

const InvictiUrls = [
  "https://netsparkercloud.com",
  "https://ie.invicti.com",
  "https://eu.netsparker.cloud",
  "https://ca.netsparker.cloud",
  "https://online.acunetix360.com",
  "https://ondemand.acunetix360.com",
  "https://novonordisk.netsparker.cloud",
  "https://hsbc.netsparker.cloud",
  "https://uat-hsbc.netsparker.cloud",
  "https://desjardins-ca.netsparker.cloud",
  "https://preproduction.netsparker.cloud",
  "https://demo.netsparker.cloud",
  "https://test.netsparker.cloud",
  "https://ie-capitalone.invicti.com",
];

function isBaseUrlValid(baseUrl) {
  try {
    let normalizedUrl = baseUrl;
    
    if (baseUrl.startsWith('https://www.')) {
      normalizedUrl = baseUrl.replace('https://www.', 'https://');
    }
    
    if (normalizedUrl.endsWith('/')) {
      normalizedUrl = normalizedUrl.slice(0, -1);
    }
    
    if (InvictiUrls.includes(normalizedUrl)) {
      return true;
    }

    // Check against the dynamic pattern 172-*-*-*.netsparker.cloud for Feature Branch Environments
    const url = new URL(baseUrl);
    const hostname = url.hostname;
    const regex = /^172(-\d{1,3}){3}\.netsparker\.cloud$/;

    if (regex.test(hostname)) {
      return true;
    }
  } catch (e) {
    core.setFailed(`Invalid URL: ${baseUrl}. Error: ${e.message}`);
    return false;
  }

  return false;
}

function isEmpty(str) {
  return (!str || str === '');
}

function getScanType(scanTypeEnum) {
  switch (scanTypeEnum) {
    case scanTypes.INCREMENTAL:
      return scanTypes.INCREMENTAL;
    case scanTypes.PRIMARY:
      return scanTypes.PRIMARY;
    case scanTypes.SELECTED:
      return scanTypes.SELECTED;
    default:
      return scanTypes.EMPTY;
  }
}

function isScanTypeValid(scanType) {
  return (
      scanType === scanTypes.PRIMARY ||
      scanType === scanTypes.INCREMENTAL ||
      scanType === scanTypes.SELECTED
  );
}

function getVulnerabilityLevel(vulnerabilityLevelEnum) {
  switch (vulnerabilityLevelEnum) {
    case VULNERABILITY_LEVELS.CRITICAL:
      return VULNERABILITY_LEVELS.CRITICAL;
    case VULNERABILITY_LEVELS.HIGH:
      return VULNERABILITY_LEVELS.HIGH;
    case VULNERABILITY_LEVELS.MEDIUM:
      return VULNERABILITY_LEVELS.MEDIUM;
    case VULNERABILITY_LEVELS.LOW:
      return VULNERABILITY_LEVELS.LOW;
    case VULNERABILITY_LEVELS.NONE:
      return VULNERABILITY_LEVELS.NONE;
    default:
      return VULNERABILITY_LEVELS.NONE;
  }
}

function getSeverityLevel(severityLevelEnum) {
  switch (severityLevelEnum) {
    case SEVERITY_LEVELS.CRITICAL:
      return SEVERITY_LEVELS.CRITICAL;
    case SEVERITY_LEVELS.HIGH:
      return SEVERITY_LEVELS.HIGH;
    case SEVERITY_LEVELS.MEDIUM:
      return SEVERITY_LEVELS.MEDIUM;
    case SEVERITY_LEVELS.LOW:
      return SEVERITY_LEVELS.LOW;
    case SEVERITY_LEVELS.BEST_PRACTICE:
      return SEVERITY_LEVELS.BEST_PRACTICE;
    case SEVERITY_LEVELS.NONE:
      return SEVERITY_LEVELS.NONE;
    default:
      return SEVERITY_LEVELS.NONE;
  }
}

function isVulnerabilityLevelValid(vulnerabilityLevel) {
  return (
      vulnerabilityLevel === SEVERITY_LEVELS.CRITICAL ||
      vulnerabilityLevel === SEVERITY_LEVELS.HIGH ||
      vulnerabilityLevel === SEVERITY_LEVELS.MEDIUM ||
      vulnerabilityLevel === SEVERITY_LEVELS.LOW ||
      vulnerabilityLevel === SEVERITY_LEVELS.BEST_PRACTICE ||
      vulnerabilityLevel === SEVERITY_LEVELS.NONE
  );
}

function needsProfile(scanType) {
  return (
      scanType === scanTypes.INCREMENTAL ||
      scanType === scanTypes.SELECTED
  );
}

function verifyInputs(websiteIdInput, scanTypeInput, userIdInput, apiTokenInput, scanType, profileIdInput, failOnLevel, waitForCompletion) {

  if (isEmpty(websiteIdInput)) {
    core.setFailed(`Input website-id is empty.`);
    return -1;
  }

  if (isEmpty(userIdInput)) {
    core.setFailed(`Input user-id is empty.`);
    return -1;
  }

  if (isEmpty(apiTokenInput)) {
    core.setFailed(`Input api-token is empty.`);
    return -1;
  }

  if (isEmpty(scanTypeInput)) {
    core.setFailed(`Input scan-type is empty.`);
    return -1;
  }

  if (!isScanTypeValid(scanType)) {
    core.setFailed(`Input scan-type is not valid: ${scanTypeInput}`);
    return -1;
  }

  if (isEmpty(failOnLevel)) {
    core.setFailed(`Input fail-on-level is empty.`);
    return -1;
  }

  if (!isVulnerabilityLevelValid(failOnLevel)) {
    core.setFailed(`Input fail-on-level is not valid: ${failOnLevel}`);
    return -1;
  }

  if(isEmpty(waitForCompletion)){
    core.setFailed(`Input wait-for-completion is empty.`);
    return -1;
  }


  if (needsProfile(scanType) && isEmpty(profileIdInput)) {
    core.setFailed(`Input profile-id is empty.`);
    return -1;
  }
  console.log("Inputs are valid.");
  return 0;
}

function prepareRequestData(websiteIdInput, scanType, profileIdInput) {
  return qs.stringify({
    'ProfileId': profileIdInput, 'ScanType': scanType, 'WebsiteId': websiteIdInput, "VcsCommitInfoModel": {
      "CiBuildConfigurationName": `${process.env.GITHUB_REPOSITORY}`, "CiBuildHasChange": `${process.env.GITHUB_SHA}`, "CiBuildId": `${process.env.GITHUB_RUN_NUMBER}`,
      "CiBuildUrl": `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`, "Committer": `${process.env.GITHUB_ACTOR}`,
      "IntegrationSystem": "GithubActions", "VcsName": "Git", "VcsVersion": `${process.env.GITHUB_SHA}`
    }
  });
}

async function scanRequest(websiteIdInput, scanTypeInput, userIdInput, apiTokenInput, profileIdInput, baseUrl, failOnLevel, waitForCompletion) {
  try {
    const scanStatusBaseUrl = baseUrl + scanStatusPath;
    const scanRequestEndpoint = baseUrl + createScanRequestEndpoint;

    const scanType = getScanType(scanTypeInput);

    if (verifyInputs(websiteIdInput, scanTypeInput, userIdInput, apiTokenInput, scanType, profileIdInput, failOnLevel, waitForCompletion) === -1) {
      return -99;
    }

    var requestData = prepareRequestData(websiteIdInput, scanType, profileIdInput);

    var config = {
      method: requestType.POST,
      url: scanRequestEndpoint,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${Buffer.from(`${userIdInput}:${apiTokenInput}`).toString('base64')}` },
      data: requestData
    };

    console.log("Requesting scan...");

    await axios(config)
        .then(function (response) {
          try {
            var result = JSON.parse(JSON.stringify(response.data));
          } catch (error) {
            core.error("Error parsing JSON %s", error.message);
            throw error;
          }

          if (result.IsValid) {
            process.env['CURRENT_SCAN_ID'] = result.ScanTaskId;
            core.setOutput('scan-message', `Scan details are available at ${String(scanStatusBaseUrl + result.ScanTaskId)}`);
            return 0;
          } else {
            throw result;
          }
        }).catch(function (error) {
          if (error.response === undefined) {
            core.setFailed(`Error: ${error.syscall} ${error.code}  Hostname: ${error.hostname}`);
            return -2
          } else if (error.response.data != null && !error.response.data.IsValid) {
            if (isEmpty(error.response.data.ErrorMessage)) {
              core.setFailed(`Scan could not be created. Check error: ${error.response.data}`);
            } else {
              core.setFailed(`Scan could not be created. Check error message: ${error.response.data.ErrorMessage}`);
            }
            return -3;
          }
          core.setFailed(`Error: ${error}`);
          return -4;
        });
  } catch (error) {
    core.setFailed(error.message);
    return -5;
  }
}

async function statusCheck(scanId, userIdInput, apiTokenInput, baseUrl) {
  try {
    let scanStatusBaseUrl = baseUrl + scanStatusEndpoint + scanId;

    const config = {
      method: requestType.GET,
      url: scanStatusBaseUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${userIdInput}:${apiTokenInput}`).toString('base64')}`
      }
    };

    const response = await axios(config);
    return response.data;
  } catch (error) {
    core.error(`Error occurred during scan status check: ${error.message}`);
    throw error; // Rethrow the error to propagate it
  }
}

async function getScanReport(scanId, userIdInput, apiTokenInput, baseUrl) {
  try {
    // Regex to validate the scanId as a GUID without hyphens
    const guidRegex = /^[0-9a-fA-F]{32}$/;
    if (!guidRegex.test(scanId)) {
      core.setFailed("Invalid scanId format. The scanId must be a 32-character GUID without hyphens.");
      return;
    }

    let type = "Crawled"; // Crawled, ExecutiveSummary
    let format = "Xml"; // Html, Pdf, Xml, Csv, Json, Txt
    let scanResultBaseUrl = baseUrl + `/api/1.0/scans/report?Id=${scanId}&type=${type}&format=${format}`;
    console.log(`Getting scan result from: ${scanResultBaseUrl}`);
    const config = {
      method: requestType.GET,
      url: scanResultBaseUrl ,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${userIdInput}:${apiTokenInput}`).toString('base64')}`
      }
    };

    const response = await axios(config);
    let content = response.data;

    let artifactName = `scan-result-${scanId}-${type}.${format}`;
    let artifactPath = path.join('.', artifactFileName);
    fs.writeFileSync(artifactPath, content);

    const artifact = new DefaultArtifactClient();
    await artifact.uploadArtifact(artifactName, [artifactName], '.');
    return artifactName;
  } catch (error) {
    core.error(`Error occurred during scan result retrieval: ${error.message}`);
    throw error; // Rethrow the error to propagate it
  }
}

function prepareScanInfoRequestData(scanId) {
  let data = {
    'ScanId': scanId,
    'DoNotFail': false,
    'IsConfirmed': false,
    'IgnoredVulnerabilityStateFilters': {
      'Present': false,
      'FixedUnconfirmed': false,
      'FixedConfirmed': false,
      'FixedCantRetest': false,
      'Revived': false,
      'Ignored': false,
      'Scanning': false,
      'AcceptedRisk': false,
      'FalsePositive': false,
    }
  };
  return qs.stringify(data);
}


async function getScanInfo(scanId, userIdInput, apiTokenInput, baseUrl) {
  try {
    let scanInfoBaseUrl = baseUrl + scanInfoEndpoint;
    console.log(`Getting scan info from: ${scanInfoBaseUrl}`);

    let requestData = prepareScanInfoRequestData(scanId);

    const config = {
      method: requestType.POST,
      url: scanInfoBaseUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${userIdInput}:${apiTokenInput}`).toString('base64')}`
      },
      data: requestData
    };

    const response = await axios(config);

    if(response.data.IsValid){
      return response.data;
    } else {
      core.error(`Scan info could not be retrieved. Check error message: ${response.data.ErrorMessage}`);
      return null;
    }
  } catch (error) {
    core.error(`Error occurred during scan info retrieval: ${error.message}`);
    throw error; // Rethrow the error to propagate it
  }
}

async function main() {
  const websiteIdInput = core.getInput('website-id');
  const scanTypeInput = core.getInput('scan-type');
  const profileIdInput = core.getInput('profile-id');
  const userIdInput = core.getInput('user-id');
  const apiTokenInput = core.getInput('api-token');
  const failOnLevel = core.getInput('fail-on-level');
  const waitForCompletion = core.getInput('wait-for-completion');
  const baseUrl = core.getInput('base-url');

  if (isEmpty(baseUrl)) {
    core.setFailed(`Base URL is missing. Please check your generated script.`);
    return;
  }

  if (!isBaseUrlValid(baseUrl)) {
    core.setFailed(`Base URL is not valid. It must be a known Invicti URL or match the pattern 172-*-*-*.netsparker.cloud.`);
    return;
  }

  // Scan request
  try {
    const scanResult = await scanRequest(websiteIdInput, scanTypeInput, userIdInput, apiTokenInput, profileIdInput, baseUrl, failOnLevel, waitForCompletion);
    if (scanResult < 0) {
      core.setFailed(`Scan request failed with error code: ${scanResult}`);
      return;
    }
  } catch (error) {
    core.setFailed(error);
    return;
  }

  // Scan ID
  let currentScanId = process.env['CURRENT_SCAN_ID'];
  if (isEmpty(currentScanId)) {
    core.setFailed(`Scan ID is missing. Please contact support.`);
    return;
  }

  // Scan status check

  let isScanOngoing = true;
  do {
    await new Promise(resolve => setTimeout(resolve, 10000));

    console.log("Getting scan info...");
    let scanInfo = null;
    try {
      scanInfo = await getScanInfo(currentScanId, userIdInput, apiTokenInput, baseUrl);
    } catch (error) {
      core.setFailed(`Error occurred during scan info retrieval: ${error}`);
      return;
    }
    console.log("Scan info retrieved for: " + scanInfo.ScanTaskId);

    let failOnLevelEnum = getSeverityLevel(failOnLevel);

    if (failOnLevelEnum === SEVERITY_LEVELS.NONE) {
      console.log(`No vulnerability level check is performed.`);
      isScanOngoing = true;
    } else {
      let foundedSeverityAndCounts = scanInfo.FoundedSeverityAndCounts;
      console.log(foundedSeverityAndCounts);
      if (foundedSeverityAndCounts) {
        let criticalCount = parseInt(foundedSeverityAndCounts.Critical);
        let highCount = parseInt(foundedSeverityAndCounts.High);
        let mediumCount = parseInt(foundedSeverityAndCounts.Medium);
        let lowCount = parseInt(foundedSeverityAndCounts.Low);
        let bestPracticeCount = parseInt(foundedSeverityAndCounts.BestPractice);

        let failMessage = '';

        switch (failOnLevelEnum) {
          case SEVERITY_LEVELS.CRITICAL:
            if (criticalCount > 0) {
              failMessage = `Critical vulnerabilities found: Critical: ${criticalCount}`;
            }
            isScanOngoing = false;
            break;
          case SEVERITY_LEVELS.HIGH:
            if (criticalCount > 0 || highCount > 0) {
              failMessage = `Critical or high vulnerabilities found: Critical: ${criticalCount}, High: ${highCount}`;
            }
            isScanOngoing = false;
            break;
          case SEVERITY_LEVELS.MEDIUM:
            if (criticalCount > 0 || highCount > 0 || mediumCount > 0) {
              failMessage = `Critical or high or medium vulnerabilities found: Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}`;
            }
            isScanOngoing = false;
            break;
          case SEVERITY_LEVELS.LOW:
            if (criticalCount > 0 || highCount > 0 || mediumCount > 0 || lowCount > 0) {
              failMessage = `Critical or high or medium or low vulnerabilities found: Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}`;
            }
            isScanOngoing = false;
            break;
          case SEVERITY_LEVELS.BEST_PRACTICE:
            if (criticalCount > 0 || highCount > 0 || mediumCount > 0 || lowCount > 0  || bestPracticeCount > 0) {
              failMessage = `Critical or high or medium or low or info or best practice vulnerabilities found: Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}, Best Practice: ${bestPracticeCount}`;
            }
            isScanOngoing = false;
            break;
        }

        if (!isEmpty(failMessage)) {
          core.setFailed(failMessage);
          isScanOngoing = false;
          return;
        } else {
          console.log(`No vulnerabilities found for the specified level: ${failOnLevel}. Founded severity and counts: `);
          console.log(foundedSeverityAndCounts);
          isScanOngoing = true;
        }
      } else {
        console.log(`No vulnerability level check is performed.`);
        isScanOngoing = true;
      }
    }

    console.log("Scan status: " + scanInfo.State);

    switch (scanInfo.State) {
      case 'Queued':
      case 'Scanning':
      case 'Archiving':
      case 'Delayed':
      case 'Pausing':
      case 'Paused':
      case 'Resuming':
        isScanOngoing = isScanOngoing && waitForCompletion === 'true';
        break;
      case 'Complete':
        console.log(`Scan completed.`);
        isScanOngoing = false;
        break;
      case 'Failed':
        core.setFailed(`Scan failed.`);
        isScanOngoing = false;
        break;
      case 'Cancelled':
        core.setFailed(`Scan was cancelled.`);
        isScanOngoing = false;
        break;
      default:
        core.setFailed(`Unknown scan state: ${scanInfo.State}. Please contact support.`);
        isScanOngoing = false;
        break;
    }



  } while (isScanOngoing);

  // Complete
  console.log("Done.");
}

main();
