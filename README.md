# high-entropy-string

A library for classifying strings as potential secrets.

## Installation

```bash
virtualenv venv
source venv/bin/activate
pip install high-entropy-string
```

## Usage

```
from high_entropy_string import PythonStringData

data = PythonStringData(
    string='AKAI...',
    node_type='assignment',
    target='myvar',
    patterns_to_ignore=[r'example.com'],
    entropy_patterns_to_discount=[r'/BEGIN.*PUBLIC KEY/']
)
print(data.confidence)
print(data.severity)
```
    
## Contributing

### Code of conduct

This project is governed by [Lyft's code of
conduct](https://github.com/lyft/code-of-conduct).
All contributors and participants agree to abide by its terms.

### Sign the Contributor License Agreement (CLA)

We require a CLA for code contributions, so before we can accept a pull request
we need to have a signed CLA. Please [visit our CLA
service](https://oss.lyft.com/cla)
follow the instructions to sign the CLA.

### How it works and how to help

The library classifies a string based on its liklihood of being a secret.
We nudge the confidence and severity of the string based on criterea:

1. Flags (ENTROPY_PATTERNS_TO_FLAG). Any Candidate that matches any regex in this
   list is automatically flagged as confidence/severity 3/3. If there's secret
   patterns you know conclusively are secrets, add them here.
2. Discounts (ENTROPY_PATTERNS_TO_DISCOUNT). Any Candidate that matches a regex in
   this list is discounted. If the Candidate matches multiple regexes in this
   list, it may be discounted further. This discount is used in the confidence
   calculation.
3. Secret hints (LOW_SECRET_HINTS, HIGH_SECRET_HINTS). If any target or caller
   matches a regex in these lists then it will be used as a hint that a
   Candidate is a secret. This hint is used in the confidence and severity
   calculations. LOW_SECRET_HINTS leads to a lower confidence increase and
   HIGH_SECRET_HINTS leads to a higher confidence increase.
4. Safe functions (SAFE_FUNCTION_HINTS). Any Candidate that has a caller that
   matches any string in this list will will be discounted. This is used in the
   confidence calculation.
5. Entropy. If a Candidate's confidence level can be more accurately gauged by
   a strings level of entropy, we calculate it and if the string has high
   entropy its confidence level is increased. This calculation is avoided if
   possible, as it's relatively expensive.

The concept is to eliminate noise while more easily identifying Candidates that
may be secrets. Some help we'd love to have:

1. Help with the discount regex list. The regexes in the list often match too
   much and there aren't enough that match common python strings.
2. Help with the safe functions list (and the way we match the safe functions).
   There's a lot of python functions that rarely include secrets but often
   contain high entropy strings. We currently don't identify these function
   calls very well, which leads to higher noise.
3. Add and improve string captures. We're not currently capturing all available strings
   in the AST and for some string captures we aren't capturing them as
   efficiently as we could. For instance with dicts, we capture info like:
   {'target': 'candidate'}, but don't capture: {'target': 'target': 'candidate'},
   which could lead to better categorization.

Feel free to submit issues and pull requests for anything else you think would be useful
as well.

