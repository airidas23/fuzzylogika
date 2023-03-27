# Fuzzy Logic Model for Recommendation Priority in Information Security

## Overview

This programing code presents a fuzzy logic-based model, to determine recommendation priorities for information security based on various data inputs. The model uses principles of fuzzy logic, including implication, MIN aggregation, MAX defuzzification, and other data analysis methods.

## Model Creation and Description

The model is based on three important criteria:

1. Attack severity (low, medium, high)
2. System importance (low, medium, high)
3. Access level (low, medium, high)

Additionally, the model considers the type of attack:

- DDoS
- Malware
- Phishing
- Social Engineering

The number of system inputs and fuzzy sets is 4 × 3.

## Recommendation Priority

The model's output is the recommendation priority, which can be low, medium, or high. The model allows determining the recommendation priority according to rules defined for attack outputs.

## Output results with plotly

![Informacinio saugumo modelis](https://github.com/airidas23/fuzzylogika/blob/master/newplot.png)
![Informacinio saugumo modelis](https://github.com/airidas23/fuzzylogika/blob/master/newplot%20(1).png)
![Informacinio saugumo modelis](https://github.com/airidas23/fuzzylogika/blob/master/newplot%20(2).png)
![Informacinio saugumo modelis](https://github.com/airidas23/fuzzylogika/blob/master/newplot%20(3).png)

## References 

1. Miglotoji logika paskaita Doc. dr. Agnė Paulauskaitė-Tarasevičienė
2. KNYGA mašinio mokymosi algoritmai 2021_01_26.pdf,
3. The Tipping Problem - The Hard Way, scikit-fuzzy development team [https://pythonhosted.org/scikit- fuzzy/auto_examples/plot_tipping_problem.html fbclid=IwAR0L_gZ1h6Kb_9SAxrXZ _PPv4 n80uLdZgbSsKCd8RfLW3lZzyrUdiMHiC0s]
4. Scatterplot Matrix in Python [https://plotly.com/python/splom/]

