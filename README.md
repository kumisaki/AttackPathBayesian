
# CVE2Tactic Analysis Toolkit

This project is a web-based platform for analyzing cyber attack paths in **Industrial IoT (IIoT)** environments. It supports topology modeling, vulnerability management, and probabilistic inference using Bayesian techniques, with rich visualizations of how subnets, devices, vulnerabilities, and MITRE ATT&CK elements interact.

---

## Features

- **Graph-based Attack Path Visualization**
  - Nodes include Subnets, Devices, Vulnerabilities, Techniques, and Tactics
  - Probabilistic severity visualization based on vulnerability likelihood
- **Bayesian Inference Support** (<span style='color:red'>pending</span>)
  - Intended integration with probabilistic models for threat propagation
- **Data Management Modules**
  - Import and edit network topologies
  - Add or upload devices
  - Edit vulnerabilities
- **Interactive Visual Interface**
  - Powered by Cytoscape.js
  - Modal popups for detailed node data
  - Dynamic coloring and edge labeling

---

## Project Structure

```
attack_bayesian_beta/
│
├── main.py                     # Flask app entry point
├── analysis.py                 # Attack path visualization logic
├── topology.py                 # Subnet & device topology handling
├── vulnerability.py            # Vulnerability CRUD and integration
├── requirements.txt            # Python dependencies
│
├── templates/                  # HTML templates (Jinja2)
│   ├── index.html
│   ├── base.html
│   ├── analysis_complex_path.html
│   ├── topology_add.html / edit.html
│   ├── vulnerability_list.html / edit.html
│   └── device_add_or_upload.html
│
├── uploads/                    # Directory for uploaded files
├── data/                       # Placeholder for data files (e.g. JSON, CSV)
├── utils/                      # Utility functions (if applicable)
└── README.md                   # This file
```

---

## Installation

### Requirements

- Python 3.8+
- Flask
- pymongo
- Other packages in `requirements.txt`

```bash
pip install -r requirements.txt
```

---

## Running the App

```bash
export FLASK_APP=main.py
flask run
```

Visit: [http://localhost:5000](http://localhost:5000)

---

## Data Requirements

Your MongoDB collections should include:

- `subnets`: `_id`, `label`
- `devices`: `_id`, `label`, `interfaces` (with `subnet`)
- `vulnerabilities`: `_id`, `desc`, `prob`, `parent_device_id`, `attack_techniques`
- `techniques`: `technique_id`, `technique_name`, `description`
- `tactics`: `tactic_id`, `tactic_name`, `description`
- `techniques_to_tactics`: links between `technique_id` and `tactic_id`

---

## Attack Path Example

```
[Subnet] --> [Device] --> [Vulnerability]
                             ↓
                        [Technique] --> [Tactic]
```

Each arrow represents an edge in the graph.
- Vulnerability → Device edges show `prob` labels
- Nodes are colored by risk or type

<!-- ---

## Future Enhancements

- Integration with a real Bayesian reasoning engine
- Graph export/import (GraphML, JSON)
- Real-time detection module
- Role-based user access and project versioning -->

<!-- ---

## Contributing

We welcome contributions!

- Fork the repo and submit a PR
- Suggest improvements or new visual encodings
- Help translate the UI or write documentation -->

---

## License

MIT License (Feel free to reuse and modify)

---

## Contact

For questions, customization, or collaborations, please contact the project maintainer.
