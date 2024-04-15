# Skattemelding

## Nødvendige tilgangar

For å få tilgang til å kunne levere skattemelding må du sende epost til servicedesk@digdir.no og be om at ditt organisasjonsnummer blir registrert i Samarbeidsportalen. Når det er på plass må du sende epost til skattemelding-sbs-brukerstotte@skatteetaten.no og be om tilgang til scope for levering av skattemelding for det gitte organisasjonsnummeret.

## Lokal køyring

```bash
RUST_LOG=info cargo watch -x run
```

## Spesifikasjon av prosess

Finn endpoints her:

https://idporten.no/.well-known/openid-configuration

Dokumentasjon her:

https://skatteetaten.github.io/mva-meldingen/english/idportenauthentication/#example-of-integration

OAuth2 klient må inn her:
https://sjolvbetjening.samarbeid.digdir.no/integrations

Det fungerer ikkje med redirect URL som inneheld "local" eller "127.0.0.1". Så applikasjonen må enten køyre på ein server eller få eit dynamisk DNS-navn. Sistnemnte kan ordnast med Tailscale slik:

```bash
tailscale funnel 12345
```

Redirect URL må dessutan innehalde portnummeret, så det blir til dømes https://mac.tailnnn.ts.net:443/token.

Klientkonfigurasjonen må også ha følgande:

- Difi-tjeneste: API-klient
- Scopes: openid og skatteetaten:formueinntekt/skattemelding
- Klientautentiseringsmetode: client_secret_basic
- Applikasjonstype: web
- PKCE: S256

OAuth2 authorize:

https://login.idporten.no/authorize?scope=skatteetaten%3Aformueinntekt%2Fskattemelding%20openid&client_id=4060f6d4-28ab-410d-bf14-edd62aa88dcf&redirect_uri=https%3A%2F%2Fmac.tail31c54.ts.net%3A443%2Ftoken&response_type=code&state=SgNdr4kEG_EJOptKwlwg5Q&nonce=1678988024798240&code_challenge=aFA1OAxhLtolRAYbYn0xqFUXvGncijKuXYOSQnltsaY&code_challenge_method=S256&ui_locales=nb

Retur:
https://mac.tail31c54.ts.net:443/token?code=5GyjYSmPkZAINh81\_\_DSVwHBMTNTM8U8UeVkbCv-2j0&state=SgNdr4kEG_EJOptKwlwg5Q

POST https://idporten.no/token

Retur:
{
"access*token": "ey..OQ",
"id_token": "ey..QA",
"token_type": "Bearer",
"expires_in": 119,
"refresh_token": "L*..uo",
"scope": "openid skatteetaten:formueinntekt/skattemelding"
}

Hent utkast:
GET https://idporten.api.skatteetaten.no/api/skattemelding/v2/utkast/2022/999579922
{'Authorization': 'Bearer ' + js['access_token']}

Retur:
<skattemeldingOgNaeringsspesifikasjonforespoerselResponse xmlns="no:skatteetaten:fastsetting:formueinntekt:skattemeldingognaeringsspesifikasjon:forespoersel:response:v2">
<dokumenter>
<skattemeldingdokument>
<id>SKI:755:338422757</id>
<encoding>utf-8</encoding>
<content>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2thdHRlbWVsZGluZyB4bWxucz0idXJuOm5vOnNrYXR0ZWV0YXRlbjpmYXN0c2V0dGluZzpmb3JtdWVpbm50ZWt0OnNrYXR0ZW1lbGRpbmc6dXBlcnNvbmxpZzpla3N0ZXJuOnYyIj48cGFydHNudW1tZXI+MTQ0MjkyNzkzMjwvcGFydHNudW1tZXI+PGlubnRla3RzYWFyPjIwMjI8L2lubnRla3RzYWFyPjwvc2thdHRlbWVsZGluZz4=</content>
<type>skattemeldingUpersonligUtkast</type>
</skattemeldingdokument>
</dokumenter>
</skattemeldingOgNaeringsspesifikasjonforespoerselResponse>

<id> er dokumentidentifikator.

Hent gjeldende:
GET https://idporten.api.skatteetaten.no/api/skattemelding/v2/2022/999579922
{'Authorization': 'Bearer ' + js['access_token']}

Retur:
<skattemeldingOgNaeringsspesifikasjonforespoerselResponse xmlns="no:skatteetaten:fastsetting:formueinntekt:skattemeldingognaeringsspesifikasjon:forespoersel:response:v2">
<dokumenter>
<skattemeldingdokument>
<id>SKI:755:338422757</id>
<encoding>utf-8</encoding>
<content>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2thdHRlbWVsZGluZyB4bWxucz0idXJuOm5vOnNrYXR0ZWV0YXRlbjpmYXN0c2V0dGluZzpmb3JtdWVpbm50ZWt0OnNrYXR0ZW1lbGRpbmc6dXBlcnNvbmxpZzpla3N0ZXJuOnYyIj48cGFydHNudW1tZXI+MTQ0MjkyNzkzMjwvcGFydHNudW1tZXI+PGlubnRla3RzYWFyPjIwMjI8L2lubnRla3RzYWFyPjwvc2thdHRlbWVsZGluZz4=</content>
<type>skattemeldingUpersonligUtkast</type>
</skattemeldingdokument>
</dokumenter>
</skattemeldingOgNaeringsspesifikasjonforespoerselResponse>

Hent fastsatt (etter levering og behandling):
GET https://idporten.api.skatteetaten.no/api/skattemelding/v2/fastsatt/2022/999579922
{'Authorization': 'Bearer ' + js['access_token']}

Base64 decode <content>:

<?xml version="1.0" encoding="UTF-8"?><skattemelding xmlns="urn:no:skatteetaten:fastsetting:formueinntekt:skattemelding:upersonlig:ekstern:v2"><partsnummer>1442927932</partsnummer><inntektsaar>2022</inntektsaar></skattemelding>

<partsnummer> trengs seinare.

Base64 encode skattemelding.xml og naeringsspesifikasjon.xml og lag melding som dette:

naering_as = """

<?xml version="1.0" encoding="utf-8" ?>
<skattemeldingOgNaeringsspesifikasjonRequest xmlns="no:skatteetaten:fastsetting:formueinntekt:skattemeldingognaeringsspesifikasjon:request:v2">
    <dokumenter>
        <dokument>
            <type>skattemeldingUpersonlig</type>
            <encoding>utf-8</encoding>
            <content>PD..4=</content>
        </dokument>
        <dokument>
            <type>naeringsspesifikasjon</type>
            <encoding>utf-8</encoding>
            <content>PD..4=</content>
        </dokument>
    </dokumenter>
    <dokumentreferanseTilGjeldendeDokument>
        <dokumenttype>skattemeldingUpersonlig</dokumenttype>
        <dokumentidentifikator>SKI:755:338422757</dokumentidentifikator>
    </dokumentreferanseTilGjeldendeDokument>
    <inntektsaar>2022</inntektsaar>
    <innsendingsinformasjon>
        <innsendingstype>komplett</innsendingstype>
        <opprettetAv>Tor Hovland</opprettetAv>
    </innsendingsinformasjon>
</skattemeldingOgNaeringsspesifikasjonRequest>
"""

Valider med meldinga over som XML body:
POST https://idporten.api.skatteetaten.no/api/skattemelding/v2/valider/2022/999579922
{'Authorization': 'Bearer ' + js['access_token']}
header["Content-Type"] = "application/xml"

Retur:
<skattemeldingOgNaeringsspesifikasjonResponse xmlns="no:skatteetaten:fastsetting:formueinntekt:skattemeldingognaeringsspesifikasjon:response:v2">
<dokumenter>
<dokument>
<type>skattemeldingUpersonligEtterBeregning</type>
<encoding>utf-8</encoding>
<content>PD..c+</content>
</dokument>
<dokument>
<type>naeringsspesifikasjonEtterBeregning</type>
<encoding>utf-8</encoding>
<content>PD..==</content>
</dokument>
<dokument>
<type>beregnetSkattUpersonlig</type>
<encoding>utf-8</encoding>
<content>PD..==</content>
</dokument>
<dokument>
<type>summertSkattegrunnlagForVisningUpersonlig</type>
<encoding>utf-8</encoding>
<content>PD..4=</content>
</dokument>
</dokumenter>
<avvikEtterBeregning>
<avvik>
<avvikstype>avvikSkattemelding</avvikstype>
<forekomstidentifikator>global</forekomstidentifikator>
<mottattVerdi>344940</mottattVerdi>
<beregnetVerdi>44054</beregnetVerdi>
<avvikIVerdi>300886</avvikIVerdi>
<sti>verdsettingAvAksje/samletVerdiBakAksjeneISelskapet/beloep/beloepSomHeltall</sti>
</avvik>
<avvik>
<avvikstype>avvikNaeringsopplysninger</avvikstype>
<forekomstidentifikator>global</forekomstidentifikator>
<mottattVerdi>314940</mottattVerdi>
<beregnetVerdi>269625</beregnetVerdi>
<avvikIVerdi>45315</avvikIVerdi>
<sti>egenkapitalavstemming/utgaaendeEgenkapital/beloep/beloep</sti>
</avvik>
</avvikEtterBeregning>
<veiledningEtterKontroll>
<veiledning>
<veiledningstype>N*AVVIK*ÅRSRESULTAT_EGENKAPITALAVSTEMMING</veiledningstype>
<forekomstidentifikator>global</forekomstidentifikator>
<hjelpetekst>Det er avvik mellom årsresultat og årets overskudd eller årets underskudd i egenkapitalavstemmingen.</hjelpetekst>
<betjeningsstrategi>merknadStandard</betjeningsstrategi>
<sti>resultatregnskap/aarsresultat/beloep/beloep</sti>
</veiledning>
<veiledning>
<veiledningstype>N_AVVIK_TILBAKEFØRT_SKATTEKOSTNAD</veiledningstype>
<forekomstidentifikator>global</forekomstidentifikator>
<hjelpetekst>Det er avvik mellom sum skattekostnad i resultatregnskapet og tilbakeført skattekostnad i permanente forskjeller.</hjelpetekst>
<betjeningsstrategi>merknadStandard</betjeningsstrategi>
<sti>resultatregnskap/sumSkattekostnad/beloep/beloep</sti>
</veiledning>
</veiledningEtterKontroll>
<resultatAvValidering>validertMedFeil</resultatAvValidering>
<aarsakTilValidertMedFeil>avvikSkattemelding</aarsakTilValidertMedFeil>
<aarsakTilValidertMedFeil>avvikNaeringsopplysninger</aarsakTilValidertMedFeil>
<informasjonOmUpersonligSkattesubjekt>
<erFritattForFormuesskatt>true</erFritattForFormuesskatt>
<erOmfattetAvSaerreglerForKraftforetak>false</erOmfattetAvSaerreglerForKraftforetak>
<erOmfattetAvPetroleumsskatteloven>false</erOmfattetAvPetroleumsskatteloven>
<erOmfattetAvRederiskatteordningen>false</erOmfattetAvRederiskatteordningen>
<erOmfattetAvFinansskattPaaLoennOgOverskudd>false</erOmfattetAvFinansskattPaaLoennOgOverskudd>
<harLeveringsfritak>false</harLeveringsfritak>
</informasjonOmUpersonligSkattesubjekt>
</skattemeldingOgNaeringsspesifikasjonResponse>

Hent Altinn-token
GET https://platform.altinn.no/authentication/api/v1/exchange/id-porten
{'Authorization': 'Bearer ' + js['access_token']}

Retur:
ey..EQ

Lag skattemeldingsinstans med JSON som body:
POST https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/
altinn_header = {"Authorization": "Bearer " + r.text}
{"instanceOwner": {"organisationNumber": '999579922'},
"appOwner": {
"labels": ["gr", "x2"]
}, "appId": "skd/formueinntekt-skattemelding-v2", "dueBefore": "2023-04-16", "visibleAfter": "2023-03-16",
"title": {"nb": "Skattemelding"}, "dataValues": {"inntektsaar": "2022"}}

Retur:
{
"id": "60271338/d1ba8c2b-f424-44a6-b888-8425c202b810",
"instanceOwner": {
"partyId": "60271338",
"personNumber": null,
"organisationNumber": "999579922",
"username": null
},
"appId": "skd/formueinntekt-skattemelding-v2",
"org": "skd",
"selfLinks": {
"apps": "https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810",
"platform": "https://platform.altinn.no/storage/api/v1/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810"
},
"dueBefore": "2023-04-16T00:00:00Z",
"visibleAfter": "2023-03-16T00:00:00Z",
"process": {
"started": "2023-03-16T19:46:01.8526919Z",
"startEvent": "StartEvent_1",
"currentTask": {
"flow": 2,
"started": "2023-03-16T19:46:01.9580344Z",
"elementId": "Task_1",
"name": "Utfylling",
"altinnTaskType": "data",
"ended": null,
"validated": null,
"flowType": "CompleteCurrentMoveToNext"
},
"ended": null,
"endEvent": null
},
"status": {
"isArchived": false,
"archived": null,
"isSoftDeleted": false,
"softDeleted": null,
"isHardDeleted": false,
"hardDeleted": null,
"readStatus": 1,
"substatus": null
},
"completeConfirmations": null,
"data": [
{
"id": "bd0d0fd7-73c9-46c5-a9fb-33dafe61f26f",
"instanceGuid": "d1ba8c2b-f424-44a6-b888-8425c202b810",
"dataType": "Skattemeldingsapp_v2",
"filename": null,
"contentType": "application/xml",
"blobStoragePath": "skd/formueinntekt-skattemelding-v2/d1ba8c2b-f424-44a6-b888-8425c202b810/data/bd0d0fd7-73c9-46c5-a9fb-33dafe61f26f",
"selfLinks": {
"apps": "https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810/data/bd0d0fd7-73c9-46c5-a9fb-33dafe61f26f",
"platform": "https://platform.altinn.no/storage/api/v1/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810/data/bd0d0fd7-73c9-46c5-a9fb-33dafe61f26f"
},
"size": 246,
"contentHash": null,
"locked": false,
"refs": [],
"isRead": true,
"tags": [],
"deleteStatus": null,
"fileScanResult": "Pending",
"created": "2023-03-16T19:46:02.1542743Z",
"createdBy": "481908",
"lastChanged": "2023-03-16T19:46:02.1542743Z",
"lastChangedBy": "481908"
}
],
"presentationTexts": {
"inntektsaar": "2022"
},
"dataValues": {
"inntektsaar": "2022"
},
"created": "2023-03-16T19:46:02.0092026Z",
"createdBy": "481908",
"lastChanged": "2023-03-16T19:46:02.0092026Z",
"lastChangedBy": "481908"
}

Last opp skattemelding:
POST https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810/data?dataType=skattemeldingOgNaeringsspesifikasjon
altinn_header = {"Authorization": "Bearer " + r.text}
"content-type" = "text/xml"
"Content-Disposition" = "attachment; filename=skattemelding.xml"

req_bekreftelse = endre_prosess_status(instans_data, altinn_header, "next", appnavn=altinn3_applikasjon)
def endre_prosess_status(instans_data: dict, token: dict, neste_status: str,
appnavn: str = "skd/formueinntekt-skattemelding-v2") -> str:
if neste_status not in ["start", "next", "completeProcess"]:
raise NotImplementedError

    url = f"{ALTINN_URL}/{appnavn}/instances/{instans_data['id']}/process/{neste_status}"
    r = requests.put(url, headers=token, verify=False)
    r.raise_for_status()
    return r.text

Sett status klar til bekreftelse:
PUT https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/d1ba8c2b-f424-44a6-b888-8425c202b810/process/next
altinn_header = {"Authorization": "Bearer " + r.text}

### Åpner skattemelding visningsklient for å se beregnet skattemelding med næringsspesifikasjon.

from skatteetaten_api import skattemelding_visning

url_skattemelding_visning = skattemelding_visning(instans_data, appnavn=altinn3_applikasjon)
print(url_skattemelding_visning)

### Sett statusen klar til henting av skatteetaten.

req_bekreftelse = endre_prosess_status(instans_data, altinn_header, "next", appnavn=altinn3_applikasjon)
req_bekreftelse

### Se innsending i Altinn
