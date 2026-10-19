# Machine Learning

Les modeles supervises sont Random Forest, XGBoost et LightGBM. Le moteur
retient la classe majoritaire, la confiance moyenne des modeles majoritaires
et leur accord. Isolation Forest est un signal complementaire d'ecart a la
distribution normale, pas une preuve de zero-day.

Les metriques disponibles sont dans `results/metrics/` et via `/api/metrics`.
Le test set doit rester intact ; SMOTE et autres reequilibrages sont reserves
au train set.

Les classes Web Attacks et Bots restent moins fiables sur le feature set MVP.
Cette limite est prise en compte dans le Decision Engine.
