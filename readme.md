# Yet another subconverter script for generating Clash config!

## Features:
   * "block list" for persian bad links (https://github.com/MasterKia/PersianBlocker/)
   * "white list" for persian sites (https://github.com/SamadiPour/iran-hosted-domains/)
   * Cache downloaded lists ("block list" and "white list") and control cache time
   * Automatically Use local lists ("block list" and "white list") from files in `sources\iran_domains` if they are not available from web links. you can change pathes and links in `options.yaml`

## Dependencies:
  * python 3 (https://www.python.org/downloads/)
  * subconverter (https://github.com/tindy2013/subconverter/releases)

## Usage
  * copy `options-sample.yaml` to `options.yaml` and edit it.
  * run script: `python ClashGen.py`
