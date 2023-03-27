import numpy as np
import skfuzzy as fuzz
import plotly.graph_objs as go

# Kintamųjų matmenys
ataka_sunkumas = np.arange(0, 101, 1)
sistemos_svarba = np.arange(0, 101, 1)
priegos_lygis = np.arange(0, 101, 1)
atakos_tipas = np.arange(0, 101, 1)
rekomendacijos_prioritetas = np.arange(0, 101, 1)

# Fuzzy aibes kintamieji

as_zemas = fuzz.trapmf(ataka_sunkumas, [0, 0, 30, 50])
as_vidutinis = fuzz.trimf(ataka_sunkumas, [30, 50, 70])
as_aukstas = fuzz.trapmf(ataka_sunkumas, [50, 70, 100, 100])

ss_zemas = fuzz.trapmf(sistemos_svarba, [0, 0, 30, 50])
ss_vidutinis = fuzz.trimf(sistemos_svarba, [30, 50, 70])
ss_aukstas = fuzz.trapmf(sistemos_svarba, [50, 70, 100, 100])

pl_zemas = fuzz.trapmf(priegos_lygis, [0, 0, 30, 50])
pl_vidutinis = fuzz.trimf(priegos_lygis, [30, 50, 70])
pl_aukstas = fuzz.trapmf(priegos_lygis, [50, 70, 100, 100])

at_ddos = fuzz.trapmf(atakos_tipas, [0, 0, 30, 50])
at_malware = fuzz.trimf(atakos_tipas, [30, 50, 70])
at_phishing = fuzz.trimf(atakos_tipas, [50, 70, 90])
at_social_engineering = fuzz.trimf(atakos_tipas, [70, 100, 100])

rp_zemas = fuzz.trapmf(rekomendacijos_prioritetas, [0, 0, 50, 70])
rp_vidutinis = fuzz.trimf(rekomendacijos_prioritetas, [50, 70, 100])
rp_aukstas = fuzz.trimf(rekomendacijos_prioritetas, [70, 100, 100])


# Funkcija sprendimo priemimui
def sprendimo_priemimas(atak_sunk, sist_svarb, prieg_lyg, atak_tip, rekomendacijos_prioritetas):
    # ivesties kintamieji
    as_level_zemas = fuzz.interp_membership(ataka_sunkumas, as_zemas, atak_sunk)
    as_level_vidutinis = fuzz.interp_membership(ataka_sunkumas, as_vidutinis, atak_sunk)
    as_level_aukstas = fuzz.interp_membership(ataka_sunkumas, as_aukstas, atak_sunk)

    ss_level_zemas = fuzz.interp_membership(sistemos_svarba, ss_zemas, sist_svarb)
    ss_level_vidutinis = fuzz.interp_membership(sistemos_svarba, ss_vidutinis, sist_svarb)
    ss_level_aukstas = fuzz.interp_membership(sistemos_svarba, ss_aukstas, sist_svarb)

    pl_level_zemas = fuzz.interp_membership(priegos_lygis, pl_zemas, prieg_lyg)
    pl_level_vidutinis = fuzz.interp_membership(priegos_lygis, pl_vidutinis, prieg_lyg)
    pl_level_aukstas = fuzz.interp_membership(priegos_lygis, pl_aukstas, prieg_lyg)

    at_level_ddos = fuzz.interp_membership(atakos_tipas, at_ddos, atak_tip)
    at_level_malware = fuzz.interp_membership(atakos_tipas, at_malware, atak_tip)
    at_level_phishing = fuzz.interp_membership(atakos_tipas, at_phishing, atak_tip)
    at_level_social_engineering = fuzz.interp_membership(atakos_tipas, at_social_engineering, atak_tip)

    # Taisykliu pateikimas
    # Rekomendacijos prioritetas žemas

    rp_zemas_activ = np.fmin(np.fmin(as_level_zemas, at_level_ddos), rp_zemas)
    rp_zemas_activ = np.fmax(rp_zemas_activ, np.fmin(ss_level_zemas, at_malware))
    rp_zemas_activ = np.fmax(rp_zemas_activ, np.fmin(pl_level_aukstas, at_level_social_engineering))
    rp_zemas_activ = np.fmax(rp_zemas_activ, np.fmin(pl_level_zemas, at_level_phishing))
    rp_zemas_activ = np.fmax(rp_zemas_activ, np.fmin(ss_level_zemas, at_level_ddos))

    # Rekomendacijos prioritetas vidutinis
    rp_vidutinis_active = np.fmin(ss_level_vidutinis, at_level_phishing)
    rp_vidutinis_active = np.fmax(rp_vidutinis_active, np.fmin(pl_level_vidutinis, at_level_ddos))
    rp_vidutinis_active = np.fmax(rp_vidutinis_active, np.fmin(pl_aukstas, at_level_ddos))
    rp_vidutinis_active = np.fmax(rp_vidutinis_active, np.fmin(as_level_vidutinis, at_level_malware))
    rp_vidutinis_active = np.fmax(rp_vidutinis_active, np.fmin(ss_level_vidutinis, at_level_social_engineering))

    # Rekomendacijos prioritetas aukštas
    rp_aukstas_active = np.fmax(np.fmin(as_level_aukstas, ss_level_aukstas), rp_aukstas)
    rp_aukstas_active = np.fmax(rp_aukstas_active, np.fmin(pl_aukstas, at_level_malware))
    rp_aukstas_active = np.fmax(rp_aukstas_active, np.fmin(as_level_aukstas, at_level_phishing))
    rp_aukstas_active = np.fmax(rp_aukstas_active, np.fmin(ss_level_aukstas, at_level_social_engineering))

    # Rekomendacijos prioriteto išvestis
    rp_aggregated = np.fmax(rp_zemas_activ, np.fmax(rp_vidutinis_active, rp_aukstas_active))

    # Defuzzification

    prioritetas_centroid = fuzz.defuzz(rekomendacijos_prioritetas, rp_aggregated, 'centroid')
    prioritetas_bisector = fuzz.defuzz(rekomendacijos_prioritetas, rp_aggregated, 'bisector')
    prioritetas_mom = fuzz.defuzz(rekomendacijos_prioritetas, rp_aggregated, 'mom')  # mean of maximum
    prioritetas_som = fuzz.defuzz(rekomendacijos_prioritetas, rp_aggregated, 'som')  # min of maximum
    prioritetas_lom = fuzz.defuzz(rekomendacijos_prioritetas, rp_aggregated, 'lom')  # max of maximum

    return prioritetas_lom, prioritetas_som, prioritetas_mom, prioritetas_centroid, \
           prioritetas_bisector, rp_zemas_activ, rp_vidutinis_active, rp_aukstas_active


# def prioriteto_reiksme(prioritetas):
#     if 0 <= prioritetas <= 70:
#         reiksme = "Žemas"
#         diapazonas = "[0, 0, 50, 70]"
#     elif 50 <= prioritetas <= 100:
#         reiksme = "Vidutinis"
#         diapazonas = "[50, 70, 100]"
#     elif 70 <= prioritetas <= 100:
#         reiksme = "Aukštas"
#         diapazonas = "[70, 100, 100]"
#     else:
#         reiksme = "Nežinoma"
#         diapazonas = "[]"
#
#     return reiksme, diapazonas

# Testavimas
# atak_sunk = 10
# sist_svarb = 30
# prieg_lyg = 50
# atak_tip = 10
#
# # # Papildomas testavimas su kitais duomenimis
# # atak_sunk = 80
# # sist_svarb = 80
# # prieig_lyg = 30
# # atak_tip = 20
#
# prioritetas_lom, prioritetas_som, prioritetas_mom, prioritetas_centroid, \
#            prioritetas_bisector, prioritetas, rp_zemas_activ, rp_vidutinis_active, rp_aukstas_active = sprendimo_priemimas(atak_sunk, sist_svarb,
#                                                                                           prieg_lyg, atak_tip,
#                                                                                           rekomendacijos_prioritetas)
# # reiksme, diapazonas = prioriteto_reiksme(prioritetas)
# print(f"Rekomendacijos prieritetas: {prioritetas}")
# print(f"Rekomendacijos prioritetas (Centroid): {prioritetas_centroid:.2f}")
# print(f"Rekomendacijos prioritetas (Bisector): {prioritetas_bisector:.2f}")
# print(f"Rekomendacijos prioritetas (Mean of Maximum): {prioritetas_mom:.2f}")
# print(f"Rekomendacijos prioritetas (Min of Maximum): {prioritetas_som:.2f}")
# print(f"Rekomendacijos prioritetas (Max of Maximum): {prioritetas_lom:.2f}")


# Testavimo duomenų sąrašas
test_data = [
    # {"atak_sunk": 10, "sist_svarb": 30, "prieg_lyg": 50, "atak_tip": 10}
    # {"atak_sunk": 80, "sist_svarb": 80, "prieg_lyg": 30, "atak_tip": 20},
    # {"atak_sunk": 50, "sist_svarb": 20, "prieg_lyg": 70, "atak_tip": 60},
    # {"atak_sunk": 90, "sist_svarb": 60, "prieg_lyg": 40, "atak_tip": 80},
    {"atak_sunk": 30, "sist_svarb": 40, "prieg_lyg": 90, "atak_tip": 30}
]

# Testavimo scenarijus
for i, data in enumerate(test_data, 1):
    print(f"Testavimo scenarijus {i}:")
    print(f"Atakos sunkumas: {data['atak_sunk']}, Sistemos svarba: {data['sist_svarb']}, "
          f"Prieigos lygis: {data['prieg_lyg']}, Atakos tipas: {data['atak_tip']}")

    prioritetas_lom, prioritetas_som, prioritetas_mom, prioritetas_centroid, \
    prioritetas_bisector, rp_zemas_activ, rp_vidutinis_active, rp_aukstas_active = sprendimo_priemimas(
        data['atak_sunk'], data['sist_svarb'],
        data['prieg_lyg'], data['atak_tip'],
        rekomendacijos_prioritetas)
    print(f"Rekomendacijos prioritetas (Centroid): {prioritetas_centroid:.2f}")
    print(f"Rekomendacijos prioritetas (Bisector): {prioritetas_bisector:.2f}")
    print(f"Rekomendacijos prioritetas (Mean of Maximum): {prioritetas_mom:.2f}")
    print(f"Rekomendacijos prioritetas (Min of Maximum): {prioritetas_som:.2f}")
    print(f"Rekomendacijos prioritetas (Max of Maximum): {prioritetas_lom:.2f}")
    print()

# Grafinis rezultatų atvaizdavimas

fig = go.Figure()

# Žemo prioriteto linija
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_zemas, mode='lines', name='Žemas',
                         line=dict(color='blue', width=2, dash='dash')))

# Vidutinio prioriteto linija
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_vidutinis, mode='lines', name='Vidutinis',
                         line=dict(color='green', width=2, dash='dash')))

# Aukšto prioriteto linija
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_aukstas, mode='lines', name='Aukštas',
                         line=dict(color='red', width=2, dash='dash')))

# Žemo prioriteto pateikimas
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_zemas_activ, mode='none',
                         fill='toself', fillcolor='rgba(0, 0, 255, 0.5)', showlegend=False))

# Vidutinio prioriteto pateikimas
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_vidutinis_active, mode='none',
                         fill='toself', fillcolor='rgba(0, 128, 0, 0.5)', showlegend=False))

# Aukšto prioriteto pateikimas
fig.add_trace(go.Scatter(x=rekomendacijos_prioritetas, y=rp_aukstas_active, mode='none',
                         fill='toself', fillcolor='rgba(255, 0, 0, 0.5)', showlegend=False))

# Grafiko antraštė ir ašių pavadinimai
fig.update_layout(title='Rekomendacijos prioritetas',
                  xaxis_title='Rekomendacijos prioritetas',
                  yaxis_title='Miglotosios aibės fuzzy funkcija')

# Rodyti grafiką
fig.show()
