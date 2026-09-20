---
tags:
- setfit
- sentence-transformers
- text-classification
- generated_from_setfit_trainer
widget:
- text: server 129.79.5.100;
- text: set security zones security-zone trust host-inbound-traffic system-services
    ssh
- text: access-list 102 permit ip host 2.0.0.0 host 255.0.0.0
- text: interface xe-0/3/0.1834;
- text: interface xe-0/3/0.853;
metrics:
- accuracy
pipeline_tag: text-classification
library_name: setfit
inference: true
base_model: sentence-transformers/all-MiniLM-L6-v2
---

# SetFit with sentence-transformers/all-MiniLM-L6-v2

This is a [SetFit](https://github.com/huggingface/setfit) model that can be used for Text Classification. This SetFit model uses [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) as the Sentence Transformer embedding model. A [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html) instance is used for classification.

The model has been trained using an efficient few-shot learning technique that involves:

1. Fine-tuning a [Sentence Transformer](https://www.sbert.net) with contrastive learning.
2. Training a classification head with features from the fine-tuned Sentence Transformer.

## Model Details

### Model Description
- **Model Type:** SetFit
- **Sentence Transformer body:** [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
- **Classification head:** a [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html) instance
- **Maximum Sequence Length:** 256 tokens
- **Number of Classes:** 14 classes
<!-- - **Training Dataset:** [Unknown](https://huggingface.co/datasets/unknown) -->
<!-- - **Language:** Unknown -->
<!-- - **License:** Unknown -->

### Model Sources

- **Repository:** [SetFit on GitHub](https://github.com/huggingface/setfit)
- **Paper:** [Efficient Few-Shot Learning Without Prompts](https://arxiv.org/abs/2209.11055)
- **Blogpost:** [SetFit: Efficient Few-Shot Learning Without Prompts](https://huggingface.co/blog/setfit)

### Model Labels
| Label                           | Examples                                                                                                                                                                                                                              |
|:--------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| device.hostname                 | <ul><li>'set system host-name as1border1'</li><li>'set system host-name as1border2'</li><li>'hostname as1core1'</li></ul>                                                                                                             |
| interface.admin_state           | <ul><li>'set interfaces lo0 unit 0 family inet address 1.1.1.1/32'</li><li>'set interfaces fe-0/0/0 unit 0  family inet address 1.0.1.1/24'</li><li>'set interfaces fe-0/0/1 unit 0  family inet address 10.12.11.1/24'</li></ul>     |
| service.timestamps              | <ul><li>'service timestamps debug datetime msec'</li><li>'service timestamps log datetime msec'</li><li>'service timestamps debug datetime msec'</li></ul>                                                                            |
| mgmt.http.server_enabled        | <ul><li>'no ip http server'</li><li>'no ip http server'</li><li>'no ip http server'</li></ul>                                                                                                                                         |
| mgmt.http.secure_server_enabled | <ul><li>'no ip http secure-server'</li><li>'no ip http secure-server'</li><li>'no ip http secure-server'</li></ul>                                                                                                                    |
| line.console.exec_timeout       | <ul><li>'exec-timeout 0 0'</li><li>'exec-timeout 0 0'</li><li>'exec-timeout 0 0'</li></ul>                                                                                                                                            |
| line.aux.exec_timeout           | <ul><li>'exec-timeout 0 0'</li><li>'exec-timeout 0 0'</li><li>'exec-timeout 0 0'</li></ul>                                                                                                                                            |
| acl.extended.entry              | <ul><li>'ip access-list extended BLOCK_SPOOF_IN'</li><li>'access-list 101 permit ip host 1.0.1.0 host 255.255.255.0'</li><li>'access-list 101 permit ip host 1.0.2.0 host 255.255.255.0'</li></ul>                                    |
| mgmt.ssh.version                | <ul><li>'set system services ssh'</li><li>'set security zones security-zone trust host-inbound-traffic system-services ssh'</li><li>'set security zones security-zone untrust host-inbound-traffic system-services ssh'</li></ul>     |
| control_plane.copp              | <ul><li>'set security screen ids-option untrust-screen icmp ping-death'</li><li>'set security screen ids-option untrust-screen ip source-route-option'</li><li>'set security screen ids-option untrust-screen ip tear-drop'</li></ul> |
| logging.remote_syslog           | <ul><li>'syslog {'</li><li>'syslog {'</li><li>'host 134.68.107.9 {'</li></ul>                                                                                                                                                         |
| time.ntp                        | <ul><li>'ntp {'</li><li>'ntp {'</li><li>'ntp {'</li></ul>                                                                                                                                                                             |
| time.ntp.server                 | <ul><li>'server 10.10.20.254;'</li><li>'server 129.79.5.100;'</li><li>'server 134.68.1.9 prefer;'</li></ul>                                                                                                                           |
| aaa.authentication_order        | <ul><li>'authentication-order [ radius password ];'</li><li>'authentication-order [ radius password ];'</li><li>'authentication-order [ radius password ];'</li></ul>                                                                 |

## Uses

### Direct Use for Inference

First install the SetFit library:

```bash
pip install setfit
```

Then you can load this model and run inference.

```python
from setfit import SetFitModel

# Download from the 🤗 Hub
model = SetFitModel.from_pretrained("setfit_model_id")
# Run inference
preds = model("server 129.79.5.100;")
```

<!--
### Downstream Use

*List how someone could finetune this model on their own dataset.*
-->

<!--
### Out-of-Scope Use

*List how the model may foreseeably be misused and address what users ought not to do with the model.*
-->

<!--
## Bias, Risks and Limitations

*What are the known or foreseeable issues stemming from this model? You could also flag here known failure cases or weaknesses of the model.*
-->

<!--
### Recommendations

*What are recommendations with respect to the foreseeable issues? For example, filtering explicit content.*
-->

## Training Details

### Training Set Metrics
| Training set | Min | Median | Max |
|:-------------|:----|:-------|:----|
| Word count   | 2   | 3.5003 | 13  |

| Label                           | Training Sample Count |
|:--------------------------------|:----------------------|
| aaa.authentication_order        | 7                     |
| acl.extended.entry              | 92                    |
| control_plane.copp              | 30                    |
| device.hostname                 | 54                    |
| interface.admin_state           | 1117                  |
| line.aux.exec_timeout           | 12                    |
| line.console.exec_timeout       | 12                    |
| logging.remote_syslog           | 15                    |
| mgmt.http.secure_server_enabled | 12                    |
| mgmt.http.server_enabled        | 12                    |
| mgmt.ssh.version                | 24                    |
| service.timestamps              | 24                    |
| time.ntp                        | 8                     |
| time.ntp.server                 | 24                    |

### Training Hyperparameters
- batch_size: (16, 16)
- num_epochs: (1, 1)
- max_steps: -1
- sampling_strategy: oversampling
- num_iterations: 20
- body_learning_rate: (2e-05, 1e-05)
- head_learning_rate: 0.01
- loss: CosineSimilarityLoss
- distance_metric: cosine_distance
- margin: 0.25
- end_to_end: False
- use_amp: False
- warmup_proportion: 0.1
- l2_weight: 0.01
- seed: 42
- eval_max_steps: -1
- load_best_model_at_end: False

### Training Results
| Epoch  | Step | Training Loss | Validation Loss |
|:------:|:----:|:-------------:|:---------------:|
| 0.0003 | 1    | 0.1437        | -               |
| 0.0139 | 50   | 0.0892        | -               |
| 0.0277 | 100  | 0.0301        | -               |
| 0.0416 | 150  | 0.0115        | -               |
| 0.0554 | 200  | 0.0091        | -               |
| 0.0693 | 250  | 0.0052        | -               |
| 0.0831 | 300  | 0.0039        | -               |
| 0.0970 | 350  | 0.0032        | -               |
| 0.1109 | 400  | 0.0021        | -               |
| 0.1247 | 450  | 0.002         | -               |
| 0.1386 | 500  | 0.0012        | -               |
| 0.1524 | 550  | 0.0013        | -               |
| 0.1663 | 600  | 0.0024        | -               |
| 0.1802 | 650  | 0.0013        | -               |
| 0.1940 | 700  | 0.0015        | -               |
| 0.2079 | 750  | 0.0011        | -               |
| 0.2217 | 800  | 0.0009        | -               |
| 0.2356 | 850  | 0.0011        | -               |
| 0.2494 | 900  | 0.0015        | -               |
| 0.2633 | 950  | 0.0007        | -               |
| 0.2772 | 1000 | 0.0007        | -               |
| 0.2910 | 1050 | 0.0006        | -               |
| 0.3049 | 1100 | 0.0017        | -               |
| 0.3187 | 1150 | 0.0015        | -               |
| 0.3326 | 1200 | 0.0012        | -               |
| 0.3465 | 1250 | 0.0005        | -               |
| 0.3603 | 1300 | 0.0005        | -               |
| 0.3742 | 1350 | 0.0016        | -               |
| 0.3880 | 1400 | 0.0015        | -               |
| 0.4019 | 1450 | 0.0005        | -               |
| 0.4157 | 1500 | 0.0005        | -               |
| 0.4296 | 1550 | 0.0008        | -               |
| 0.4435 | 1600 | 0.0005        | -               |
| 0.4573 | 1650 | 0.0005        | -               |
| 0.4712 | 1700 | 0.0004        | -               |
| 0.4850 | 1750 | 0.0024        | -               |
| 0.4989 | 1800 | 0.0004        | -               |
| 0.5127 | 1850 | 0.0004        | -               |
| 0.5266 | 1900 | 0.0004        | -               |
| 0.5405 | 1950 | 0.0004        | -               |
| 0.5543 | 2000 | 0.0005        | -               |
| 0.5682 | 2050 | 0.0003        | -               |
| 0.5820 | 2100 | 0.0004        | -               |
| 0.5959 | 2150 | 0.0004        | -               |
| 0.6098 | 2200 | 0.0004        | -               |
| 0.6236 | 2250 | 0.0013        | -               |
| 0.6375 | 2300 | 0.0003        | -               |
| 0.6513 | 2350 | 0.0003        | -               |
| 0.6652 | 2400 | 0.0003        | -               |
| 0.6790 | 2450 | 0.0003        | -               |
| 0.6929 | 2500 | 0.0004        | -               |
| 0.7068 | 2550 | 0.0003        | -               |
| 0.7206 | 2600 | 0.0003        | -               |
| 0.7345 | 2650 | 0.0003        | -               |
| 0.7483 | 2700 | 0.0003        | -               |
| 0.7622 | 2750 | 0.0003        | -               |
| 0.7761 | 2800 | 0.0003        | -               |
| 0.7899 | 2850 | 0.0003        | -               |
| 0.8038 | 2900 | 0.0003        | -               |
| 0.8176 | 2950 | 0.0003        | -               |
| 0.8315 | 3000 | 0.0003        | -               |
| 0.8453 | 3050 | 0.0003        | -               |
| 0.8592 | 3100 | 0.0003        | -               |
| 0.8731 | 3150 | 0.0004        | -               |
| 0.8869 | 3200 | 0.0003        | -               |
| 0.9008 | 3250 | 0.0003        | -               |
| 0.9146 | 3300 | 0.0002        | -               |
| 0.9285 | 3350 | 0.0003        | -               |
| 0.9424 | 3400 | 0.0003        | -               |
| 0.9562 | 3450 | 0.0002        | -               |
| 0.9701 | 3500 | 0.0019        | -               |
| 0.9839 | 3550 | 0.0003        | -               |
| 0.9978 | 3600 | 0.0003        | -               |

### Framework Versions
- Python: 3.10.11
- SetFit: 1.1.3
- Sentence Transformers: 5.7.0
- Transformers: 4.57.6
- PyTorch: 2.13.0+cpu
- Datasets: 5.0.1
- Tokenizers: 0.22.2

## Citation

### BibTeX
```bibtex
@article{https://doi.org/10.48550/arxiv.2209.11055,
    doi = {10.48550/ARXIV.2209.11055},
    url = {https://arxiv.org/abs/2209.11055},
    author = {Tunstall, Lewis and Reimers, Nils and Jo, Unso Eun Seo and Bates, Luke and Korat, Daniel and Wasserblat, Moshe and Pereg, Oren},
    keywords = {Computation and Language (cs.CL), FOS: Computer and information sciences, FOS: Computer and information sciences},
    title = {Efficient Few-Shot Learning Without Prompts},
    publisher = {arXiv},
    year = {2022},
    copyright = {Creative Commons Attribution 4.0 International}
}
```

<!--
## Glossary

*Clearly define terms in order to be accessible across audiences.*
-->

<!--
## Model Card Authors

*Lists the people who create the model card, providing recognition and accountability for the detailed work that goes into its construction.*
-->

<!--
## Model Card Contact

*Provides a way for people who have updates to the Model Card, suggestions, or questions, to contact the Model Card authors.*
-->