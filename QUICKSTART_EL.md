# TriageFlow v2.1.0 — Οδηγός χρήσης στα Ελληνικά

Αυτός είναι ο πρακτικός οδηγός για να ξεκινήσεις χωρίς να χρειάζεται να θυμάσαι παραμέτρους ή να γράφεις μεγάλες εντολές.

> **Χρησιμοποίησέ το μόνο** σε συστήματα που σου ανήκουν ή για τα οποία έχεις ρητή εξουσιοδότηση. Το TriageFlow δεν παρακάμπτει login και δεν προσπαθεί κωδικούς.

## 1. Η πιο απλή εκκίνηση

Σε Kali Linux ή άλλο Linux:

```bash
git clone https://github.com/CodebindPyth/TriageFlow.git
cd TriageFlow
python3 triageflow.py
```

Η τελευταία εντολή ανοίγει τον οδηγό (wizard). Δεν χρειάζεται να βάλεις αμέσως `-u`, `-w` ή άλλες παραμέτρους. Στον wizard επιλέγεις αν θα χρησιμοποιηθεί το αυτόματα εντοπισμένο wordlist (προτιμά το SecLists αν είναι ήδη εγκατεστημένο, αλλιώς χρησιμοποιεί το ενσωματωμένο) ή κάποιο δικό σου. Στη v2 μπορείς επίσης να επιλέξεις screenshots και HTML report.

Αν έχεις ήδη κατεβάσει το repository, αρκεί:

```bash
cd TriageFlow
python3 triageflow.py
```

Για να δεις όλες τις επιλογές χωρίς να ξεκινήσει έλεγχος:

```bash
python3 triageflow.py --help
```

## 2. Τι θα σε ρωτήσει ο οδηγός

### Βήμα A — Τι θα ελέγξεις;

- **1 — Έναν στόχο:** γράψε ένα domain, URL ή IP που έχεις δικαίωμα να ελέγξεις, π.χ. `example.com`.
- **2 — Αρχείο στόχων:** γράψε τη διαδρομή προς αρχείο κειμένου που έχει έναν στόχο ανά γραμμή.
- **q — Έξοδος:** ακυρώνει τον οδηγό.

Παράδειγμα αρχείου `my-targets.txt`:

```text
# Ένα domain, URL ή IP ανά γραμμή
example.com
https://staging.example.com
192.0.2.10
```

Τα παραδείγματα παραπάνω είναι ενδεικτικά. Αντικατάστησέ τα μόνο με στόχους που είναι πραγματικά εντός του εξουσιοδοτημένου scope σου.

### Βήμα B — Ποιο wordlist θα χρησιμοποιήσεις;

- **1 — Αυτόματα εντοπισμένο wordlist:** αν υπάρχει ήδη SecLists, επιλέγει το `Discovery/DNS/subdomains-top1million-5000.txt`, διαφορετικά χρησιμοποιεί το μικρό wordlist του repository. Δοκιμάζει πιθανά ονόματα subdomain και κρατά όσα επιλύονται μέσω του DNS του συστήματός σου.
- **2 — Δικό σου wordlist:** δώσε τη διαδρομή του αρχείου.
- **3 — Κανένα:** παραλείπει το wordlist. Μπορεί να συνεχίσει το Subfinder, εφόσον είναι ενεργό το επιλεγμένο προφίλ.

Ένα wordlist περιέχει ένα όνομα ή label ανά γραμμή, π.χ. `dev`, `api`, `staging`. Δεν είναι λίστα με κωδικούς. Στη v2.0.3, στις απευθείας εντολές CLI το πρόγραμμα ψάχνει πρώτα για τοπικό SecLists `Discovery/DNS/subdomains-top1million-5000.txt` και, αν δεν υπάρχει, χρησιμοποιεί το `wordlists/subdomains-small.txt` του repository όταν δεν δώσεις `-w`. Ο έλεγχος του wordlist εκτελείται πριν από το Subfinder και όσα ονόματα επιλυθούν μέσω DNS περνούν στο `all-targets.txt` και έπειτα στο `httpx`, τα live ευρήματα περνούν στα επόμενα στάδια. Για μεγαλύτερη λίστα, δώσε `-w /path/to/wordlist.txt`. Χρησιμοποίησε `--no-wordlist` για να απενεργοποιήσεις την αυτόματη επιλογή wordlist. Το DNS γίνεται παράλληλα με το ProjectDiscovery `dnsx` (100 workers, timeout 2 δευτερολέπτων, μία προσπάθεια και wildcard filtering). Αν συνεχίζει πάνω από 10 δευτερόλεπτα, τυπώνει περιοδικά μήνυμα προόδου και τη διαδρομή του log.

### Βήμα C — Ποιο προφίλ;

**Standard (προτεινόμενο):** εκτελεί όλα τα ενεργοποιημένα στάδια: Subfinder, προαιρετικό wordlist, httpx, απογραφή assets/software/version, αναζήτηση υποψήφιων CVEs στο NVD, εντοπισμό login panels, Nuclei και —αν το επιλέξεις— screenshots μέσω GoWitness.

**Quick:** παραλείπει Subfinder και Nuclei. Τα screenshots είναι απενεργοποιημένα εξ ορισμού, αλλά αμέσως μετά θα ερωτηθείς αν θέλεις να τα ενεργοποιήσεις. Το Quick εξακολουθεί να χρησιμοποιεί httpx, asset/software inventory, CVE triage και login-panel review.

### Βήμα D — Screenshots

Ο wizard ρωτά αν θέλεις screenshots των σελίδων που απάντησαν στο httpx.

- **1 — Ναι:** ενεργοποιεί το GoWitness. Χρησιμοποιεί το ίδιο `live.txt` που περιλαμβάνει και τα live subdomains που ανακαλύφθηκαν.
- **2 — Όχι:** παραλείπει αυτό το στάδιο και δεν χρειάζεται να είναι εγκατεστημένο το GoWitness.

### Βήμα E — HTML report

Διάλεξε **1** για να δημιουργήσει το `report.html`, ένα αρχείο που ανοίγει τοπικά στον browser και συγκεντρώνει τα βασικά αποτελέσματα. Διάλεξε **2** αν θέλεις μόνο CSV/JSON/Markdown.

### Βήμα F — Επιβεβαίωση εξουσιοδότησης

Πριν ξεκινήσει η σάρωση θα εμφανιστεί επιβεβαίωση. Πληκτρολόγησε ακριβώς `YES` μόνο αν οι στόχοι ανήκουν σε εσένα ή βρίσκονται σε ρητά εγκεκριμένο scope. Οτιδήποτε άλλο ακυρώνει τη σάρωση.

## 3. Τι κάνει το κάθε στάδιο;

| Στάδιο | Με απλά λόγια |
|---|---|
| **Subfinder** | Συλλέγει γνωστά subdomains από παθητικές πηγές. Η κάλυψη εξαρτάται από τις πηγές και τη ρύθμιση. |
| **Wordlist + DNS** | Δημιουργεί πιθανά subdomains από το wordlist και ελέγχει ποια ονόματα επιλύονται. Η επίλυση DNS δεν αποδεικνύει ότι υπάρχει web server. |
| **httpx** | Ελέγχει ποιοι στόχοι απαντούν μέσω HTTP/HTTPS και συλλέγει ορατές πληροφορίες όπως status, τίτλο, server και τεχνολογίες. |
| **Software inventory** | Αποθηκεύει fingerprints και εκδόσεις που έγιναν ορατές από τον στόχο. Πολλοί servers κρύβουν την ακριβή έκδοση, άρα κενή έκδοση δεν σημαίνει σφάλμα. |
| **NVD / CVEs** | Αναζητά υποψήφιες αντιστοιχίες μεταξύ software/version και καταχωρίσεων CVE. Είναι αρχικό στοιχείο για έλεγχο, όχι απόδειξη ότι ο στόχος είναι ευάλωτος. |
| **Login panels** | Ελέγχει περιορισμένο αριθμό συνηθισμένων διαδρομών login με HTTP GET. Δεν στέλνει username/password και δεν επιχειρεί σύνδεση. |
| **Nuclei** | Εκτελεί ελέγχους βάσει templates στα live URLs, με βάση τις επιλεγμένες σοβαρότητες. Τα ευρήματα χρειάζονται επαλήθευση. |
| **GoWitness** | Κρατά screenshots από τις σελίδες που απάντησαν. |

Για τα CVEs, σύγκρινε πάντα το ακριβές προϊόν, την έκδοση και το εύρος επηρεαζόμενων εκδόσεων με το advisory του κατασκευαστή. Οι πληροφορίες banner μπορεί να είναι κρυφές, ανακριβείς ή να αφορούν proxy αντί για το backend.

## 4. Πού βρίσκονται τα αποτελέσματα;

Από προεπιλογή δημιουργείται νέος φάκελος ανά εκτέλεση:

```text
triageflow-results/
└── 20261011-120000/       # παράδειγμα timestamp
    ├── README.md
    ├── summary.json
    ├── all-targets.txt
    ├── live.txt
    ├── httpx-details.jsonl
    ├── asset-inventory.csv
    ├── software-inventory.csv
    ├── login-panels.csv
    ├── default-credentials-review.md
    ├── default-credentials-review.csv
    ├── cve-candidates.md
    ├── cve-candidates.json
    ├── nuclei-findings.jsonl
    ├── report.html
    ├── gowitness/
    └── *.log
```

Το timestamp παραπάνω είναι μόνο παράδειγμα· ο δικός σου φάκελος θα έχει ημερομηνία/ώρα εκτέλεσης.

**Από πού να ξεκινήσεις όταν τελειώσει;**

1. Άνοιξε το `report.html` με τον browser. Είναι το πιο εύκολο σημείο για να δεις συνολικά τα αποτελέσματα.
2. Άνοιξε το `README.md` ή το `summary.json` για το ποιες εργασίες ολοκληρώθηκαν και αν υπήρξαν errors.
3. Άνοιξε το `asset-inventory.csv` για τις υπηρεσίες και τις διευθύνσεις που εντοπίστηκαν.
4. Άνοιξε το `software-inventory.csv` και το `cve-candidates.md` για εκδόσεις και υποψήφιες CVE αντιστοιχίες.
5. Άνοιξε το `login-panels.csv` και το `default-credentials-review.md` για τα login panels και τις προτεινόμενες χειροκίνητες ερωτήσεις ασφαλείας.
6. Άνοιξε το `nuclei-findings.jsonl` για τα ευρήματα Nuclei ή τα `*.log` αν κάποιο στάδιο απέτυχε.

Για να δεις τα αποτελέσματα από το terminal στο Kali:

```bash
ls -lt triageflow-results
```

Για να δεις τη σύνοψη του πιο πρόσφατου φακέλου:

```bash
latest="$(find triageflow-results -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
cat "$latest/README.md"
```

Μην ανεβάζεις δημόσια αποτελέσματα σάρωσης χωρίς έλεγχο. Logs και screenshots μπορεί να περιέχουν εσωτερικά ονόματα host, προσωπικά δεδομένα ή ευαίσθητες πληροφορίες.

## 5. Εναλλακτικά, χωρίς wizard

Αφού εξοικειωθείς, μπορείς να δώσεις τις παραμέτρους κατευθείαν.

```bash
# Το SecLists επιλέγεται αν υπάρχει· αλλιώς χρησιμοποιείται το ενσωματωμένο wordlist
python3 triageflow.py -u example.com

# Παράλειψη της αυτόματης επιλογής wordlist
python3 triageflow.py -u example.com --no-wordlist

# Χρήση μεγαλύτερου δικού σου wordlist
python3 triageflow.py -u example.com -w /path/to/subdomains.txt

# Πολλοί στόχοι από αρχείο
python3 triageflow.py -l my-targets.txt

# Γρήγορη εκτέλεση: χωρίς Subfinder, Nuclei και screenshots
python3 triageflow.py -u example.com \
  --no-subdomains --no-nuclei --no-screenshots

# Παράλειψη μόνο του ελέγχου login panels και της αναζήτησης CVE
python3 triageflow.py -u example.com --no-login-check --no-cve-lookup
```

Οι παραπάνω εντολές ελέγχουν πραγματικούς προορισμούς. Χρησιμοποίησε αντικαταστάσεις όπως `example.com` μόνο για κατανόηση σύνταξης, όχι ως άδεια για δοκιμή συστημάτων τρίτων.

## 6. Εργαλεία και εγκατάσταση

Το Python μέρος χρησιμοποιεί standard library και δεν χρειάζεται `pip install -r requirements.txt` για να τρέξει. Για screenshots χρειάζεται επίσης εγκατεστημένο Chrome ή Chromium. Η v2 εμφανίζει προειδοποίηση πριν ξεκινήσει αν έχεις επιλέξει screenshots αλλά δεν βρίσκει browser στο `PATH`. Πριν εγκαταστήσει εργαλεία, ελέγχει αν υπάρχουν ήδη στο `PATH`, στο `~/go/bin` ή στους καταλόγους `GOBIN`/`GOPATH`. Το pipeline χρησιμοποιεί ξεχωριστά εκτελέσιμα εργαλεία: ProjectDiscovery `httpx`, `subfinder`, `nuclei`, `dnsx`, `ffuf` και `gowitness` ανάλογα με τα στάδια.

Αν το Go είναι εγκατεστημένο, το TriageFlow πρώτα ελέγχει τα ήδη διαθέσιμα executables και προσπαθεί να εγκαταστήσει με Go μόνο όσα εργαλεία λείπουν πραγματικά. Αν δεν θέλεις να εγκαταστήσεις Chrome/Chromium ή να χρησιμοποιήσεις browser automation, επίλεξε screenshots = Όχι στον wizard. Χρειάζεται σύνδεση στο Internet και η εγκατάσταση μπορεί να αποτύχει λόγω έκδοσης Go, δικτύου ή συμβατότητας. Αν το μήνυμα λέει ότι λείπει το Go, εγκατέστησέ το από τις επίσημες οδηγίες ή τον package manager της διανομής σου και ξανατρέξε το πρόγραμμα.

Για έλεγχο εκδόσεων:

```bash
python3 --version
go version
```

## 7. Συχνά προβλήματα

### «Required tools unavailable» ή εργαλείο που λείπει

Διάβασε ποια ονόματα εργαλείων αναφέρονται στο μήνυμα. Έλεγξε ότι υπάρχει Go με `go version`, ότι υπάρχει σύνδεση Internet και ξανατρέξε το TriageFlow. Αν συνεχίζει να αποτυγχάνει, δες το σχετικό `*.log` ή το μήνυμα εγκατάστασης.

### Δεν βρίσκει subdomains ή φαίνεται να κολλάει στο wordlist

Η v2.0.4 χρησιμοποιεί `dnsx` για παράλληλα DNS checks και γράφει μηνύματα προόδου στο terminal και διαγνωστικά στο `dnsx.log`. Το `wordlist-candidates.txt` περιέχει τα ονόματα που δημιούργησε από το wordlist· το `wordlist-resolved.txt` έχει όσα απάντησαν μέσω DNS. Έπειτα το `httpx` ελέγχει ποια από αυτά έχουν HTTP/HTTPS υπηρεσία. Στη v2.0.7, τα εξωτερικά εργαλεία εμφανίζουν μήνυμα προόδου ανά 10 δευτερόλεπτα όσο τρέχουν· στο στάδιο `httpx` εμφανίζεται και ο αριθμός JSONL αποτελεσμάτων που έχουν γραφτεί μέχρι εκείνη τη στιγμή. Ο αριθμός αυτός δείχνει καταγεγραμμένες HTTP απαντήσεις, όχι όλα τα αιτήματα που έχουν ήδη δοκιμαστεί.

Αν δουλεύεις με lab domain όπως `inlanefreight.local`, βεβαιώσου ότι το Kali χρησιμοποιεί τον DNS resolver του lab. Πριν αρχίσει το DNS, το πρόγραμμα δείχνει το ακριβές path του wordlist και πόσες γραμμές εισόδου έχει. Το επίσημο `subdomains-top1million-5000.txt` έχει 5.000 γραμμές· αν δεις περίπου 100.000 candidates, έλεγξε μήπως χρησιμοποιείται διαφορετικό/μεγαλύτερο αρχείο. Οι scoped/link-local IPv6 nameservers όπως `fe80::1%eth1` αγνοούνται, επειδή δεν είναι ασφαλές να περαστούν έτσι στη λίστα resolver του dnsx. Η v2 διαβάζει τους υπόλοιπους resolvers από `/etc/resolv.conf` και ελέγχει και το system hosts file. Αν το lab δίνει διαφορετικό DNS server, πέρασέ τον ρητά, π.χ.:

```bash
python3 triageflow.py -u inlanefreight.local -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --dns-resolvers 10.0.0.1
```

Αντικατάστησε το `10.0.0.1` με την πραγματική DNS IP που παρέχει το lab. Μην υποθέτεις ότι αυτή η IP είναι σωστή για το δικό σου περιβάλλον.

Για να εξακριβώσεις ποιο αρχείο χρησιμοποιήθηκε και πόσο μεγάλο είναι, σταμάτησε την τρέχουσα εκτέλεση με `Ctrl+C` και έλεγξε:

```bash
wc -l /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
wc -l /home/kali/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
wc -l triageflow-results/20261011-115310/wordlist-candidates.txt
```

Η τελευταία διαδρομή είναι παράδειγμα από ένα run· βάλε τον πραγματικό φάκελο αποτελεσμάτων σου. Το μήνυμα προόδου ανά 10 δευτερόλεπτα σημαίνει ότι το `dnsx` δεν έχει ολοκληρώσει ακόμη, όχι ότι βρήκε ευρήματα. Το ίδιο ισχύει για το `httpx`: μπορεί να συνεχίζει να ελέγχει targets ακόμη και όταν δεν έχει καταγραφεί νέα HTTP απάντηση. Περίπου 100.000 candidates με όριο 50 requests/sec χρειάζονται τουλάχιστον 33 λεπτά μόνο με βάση το rate limit, χωρίς καθυστερήσεις DNS ή συνδέσεων.

Το `.local` συνήθως ανήκει σε εσωτερικό/lab namespace, οπότε το Subfinder μπορεί να μην επιστρέψει παθητικά subdomains από δημόσιες πηγές. Επίσης, το ότι ένα όνομα απαντά στο DNS δεν σημαίνει ότι έχει web service· αυτό ελέγχεται στο επόμενο στάδιο με httpx.

### Απευθείας VHost brute-force χωρίς dnsx

Αν θέλεις να δοκιμάζεις τα ονόματα απευθείας μέσω HTTP Host header, χωρίς να περάσουν πρώτα από DNS resolution με το dnsx, χρησιμοποίησε το ξεχωριστό script `vhost_direct.py`. Χρειάζεται το ffuf, όχι το dnsx ή το Subfinder.

```bash
python3 vhost_direct.py \
  -u http://inlanefreight.local/ \
  -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  --rate 100 \
  --max-time 120
```

Το wordlist πρέπει να έχει ένα label ανά γραμμή (π.χ. admin, dev, portal). Το URL βάσης πρέπει να είναι προσβάσιμο από το Kali. Πριν στείλει αιτήματα, το script ζητά επιβεβαίωση εξουσιοδότησης. Τα αποτελέσματα αποθηκεύονται σε νέο timestamped φάκελο κάτω από `triageflow-results/`: `vhost-findings.csv`, `vhost-findings.json`, `vhost-subdomains.txt` και `ffuf-vhost.log`. Είναι ξεχωριστά από το `live.txt` του βασικού pipeline.

### Brute-force στο κανονικό `triageflow.py` χωρίς ξεχωριστό dnsx

Η επιλογή `--bruteforce-direct` στέλνει τους υποψήφιους hostnames από το wordlist κατευθείαν στο `httpx`, παρακάμπτοντας μόνο το ξεχωριστό στάδιο προεπίλυσης `dnsx`. Το Subfinder συνεχίζει να τρέχει κανονικά, εκτός αν δώσεις `--no-subdomains`. Το `httpx` εξακολουθεί να χρειάζεται DNS resolution εσωτερικά για να συνδεθεί σε hostname.

```bash
python3 triageflow.py \
  -u http://inlanefreight.local/ \
  -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --bruteforce-direct \
  --bruteforce-rate 10
```

Η λειτουργία παρακάμπτει μόνο την ανεξάρτητη προεπίλυση `dnsx`, αλλά διατηρεί το Subfinder εκτός αν επιλέξεις `--no-subdomains`. Εξ ορισμού είναι ενεργά τα login-panel checks, το CVE lookup, το Nuclei, τα screenshots μέσω GoWitness και το HTML report. Κάθε στάδιο απενεργοποιείται σκόπιμα με το αντίστοιχο `--no-login-check`, `--no-cve-lookup`, `--no-nuclei` ή `--no-screenshots`. Το όριο του `httpx` είναι προεπιλεγμένα 50 αιτήματα/δευτερόλεπτο και αλλάζει με `--bruteforce-rate`. Τα `wordlist-candidates.txt` και `wordlist-live.txt` αποθηκεύουν αντίστοιχα τους υποψήφιους hosts και όσους επέστρεψαν live HTTP αποτέλεσμα. Το HTML report εμφανίζει τα screenshots από τον γειτονικό φάκελο `gowitness/`, οπότε κράτησέ τον μαζί με το `report.html`. Χρησιμοποίησέ το μόνο σε στόχους που ανήκουν σε εγκεκριμένο scope.

### Virtual-host discovery όταν η DNS αναζήτηση επιστρέφει μηδέν

Σε ορισμένα lab περιβάλλοντα, όπως το `inlanefreight.local`, ο web server μπορεί να εξυπηρετεί διαφορετικές εφαρμογές ανάλογα με το HTTP `Host` header, παρότι τα αντίστοιχα ονόματα δεν έχουν ξεχωριστές DNS εγγραφές. Σε αυτήν την περίπτωση το DNS wordlist δεν αρκεί.

Αν το DNS και το Subfinder δεν βρουν subdomains, το TriageFlow σε ρωτά αν θέλεις να δοκιμάσει virtual-host discovery με το `ffuf`. Πληκτρολόγησε ακριβώς `YES` για να το εγκρίνεις.

Μπορείς να το ενεργοποιήσεις απευθείας με την επιλογή `--vhost-fuzz`:

```bash
python3 triageflow.py -u http://inlanefreight.local/ --no-subdomains \
  -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --vhost-fuzz
```

Η παραπάνω εντολή πρέπει να χρησιμοποιείται μόνο στο εγκεκριμένο lab. Το `ffuf` στέλνει HTTP αιτήματα με διαφορετικές τιμές στο `Host` header, μέχρι 100 αιτήματα/δευτερόλεπτο και με μέγιστο χρόνο 120 δευτερολέπτων ανά root. Τα ευρήματα αποθηκεύονται στα `vhost-findings.csv`, `vhost-findings.json` και `vhost-subdomains.txt` και εμφανίζονται στο `report.html`.

Τα virtual-host ονόματα μπορεί να μην επιλύονται μέσω DNS. Γι’ αυτό δεν μπαίνουν αυτόματα στο `live.txt` ούτε στα GoWitness screenshots· τα αποτελέσματά τους παρουσιάζονται ξεχωριστά.

### Το NVD δεν επιστρέφει αποτελέσματα ή εμφανίζει rate limit

Αυτό μπορεί να συμβεί επειδή δεν εντοπίστηκε συγκεκριμένη έκδοση, υπάρχει περιορισμός αιτημάτων ή η υπηρεσία δεν είναι διαθέσιμη. Δεν σημαίνει ότι ο στόχος είναι ασφαλής. Το NVD API key είναι προαιρετικό· αν χρησιμοποιήσεις ένα, κράτησέ το ως μεταβλητή περιβάλλοντος και **μην το βάλεις σε κώδικα ή GitHub**.

### Δεν βρέθηκαν login panels

Η v2.0.9 ελέγχει αρχικά την αρχική σελίδα, συνηθισμένες διαδρομές login και συνδέσμους ίδιας προέλευσης (same-origin) με ενδείξεις login/account/portal που βρίσκονται στο HTML. Μπορεί να καταγράψει περισσότερες από μία login pages ανά origin, με όριο 8 panels και 40 αιτήματα σελίδων ανά origin και έως 25 origins εξ ορισμού. Το `login-discovery-summary.json` δείχνει πόσα origins και URLs ελέγχθηκαν, πόσες HTML σελίδες διαβάστηκαν και πόσα login-like links εντοπίστηκαν. Ελέγχονται μόνο redirects προς την ίδια προέλευση και δεν στέλνονται credentials. Αυτό εξακολουθεί να μην εγγυάται την εύρεση login pages που εμφανίζονται αποκλειστικά με JavaScript ή βρίσκονται πίσω από μη συνδεδεμένες/custom διαδρομές. Αν ο έλεγχος έχει απενεργοποιηθεί, αποτύχει ή δεν εκτελεστεί επειδή δεν βρέθηκαν live URLs, το checklist και το HTML report το δηλώνουν ρητά αντί να αναφέρουν ότι δεν βρέθηκε login page.

### Πώς να καταλάβω τα αποτελέσματα CVE;

Στο `cve-candidates.md` η v2 ξεχωρίζει τα CPE applicability hints από τα keyword-only matches. Το πρώτο σημαίνει ότι τα CPE criteria που περιέχονται στα αποτελέσματα του NVD φαίνεται να ταιριάζουν με την παρατηρημένη έκδοση. Παραμένει ένδειξη για επιβεβαίωση και όχι απόδειξη ευπάθειας. Το keyword-only σημαίνει ότι βρέθηκε σχετική λέξη/φράση, αλλά δεν βρέθηκε αντίστοιχη CPE ένδειξη στα συγκεκριμένα αποτελέσματα.

### Τι σημαίνει το default-credentials review;

Το `default-credentials-review.md` δεν κάνει login και δεν δοκιμάζει κωδικούς. Δίνει στα panels που εντόπισε ένα checklist για επιβεβαίωση ότι άλλαξαν οι αρχικοί κωδικοί, απενεργοποιήθηκαν άχρηστοι λογαριασμοί, ενεργοποιήθηκε MFA όπου υποστηρίζεται και περιορίστηκε η πρόσβαση στα admin panels. Για πραγματικό έλεγχο, ακολούθησε την εγκεκριμένη διαδικασία του οργανισμού ή δοκίμασε σε ξεχωριστό lab.

### Τα CVE ή τα Nuclei findings μοιάζουν ύποπτα

Αντιμετώπισέ τα ως υποψήφια ευρήματα. Έλεγξε προϊόν, έκδοση, επηρεαζόμενο εύρος, vendor advisory και συνθήκες αναπαραγωγής μέσα στο εξουσιοδοτημένο περιβάλλον.

### Το apt αναφέρει ότι το dpkg διακόπηκε

Αν αυτό συμβεί κατά την προετοιμασία του Kali, ακολούθησε πρώτα την ανάκτηση του package manager:

```bash
sudo dpkg --configure -a
sudo apt --fix-broken install
```

Έπειτα επανάλαβε την εντολή εγκατάστασης που χρειαζόσουν.

## 8. Βασικές αρχές

- Εκτέλεσε έλεγχο μόνο σε δικά σου ή γραπτώς εξουσιοδοτημένα συστήματα.
- Επίλεξε το μικρότερο scope που χρειάζεσαι και σεβάσου τα όρια του προγράμματος/bug bounty.
- Μην θεωρείς την απουσία ευρημάτων απόδειξη ασφάλειας.
- Μην θεωρείς μία CVE keyword match ή CPE heuristic απόδειξη ευπάθειας.
- Το εργαλείο δεν δοκιμάζει default credentials· το checklist βοηθά σε χειροκίνητο, εγκεκριμένο configuration audit. Η ανίχνευση login pages γίνεται με GET requests και δεν πραγματοποιεί authentication.
- Προστάτευσε τα CSV, logs και screenshots και μην τα δεσμεύεις στο Git.
- Για συνεισφορές, διάβασε το [CONTRIBUTING.md](CONTRIBUTING.md).

Για προβλήματα ή ιδέες, άνοιξε GitHub issue και αφαίρεσε πρώτα tokens, API keys και ευαίσθητα στοιχεία στόχων.


## 9. Διαδραστικός χάρτης attack surface

Από προεπιλογή, το TriageFlow δημιουργεί `attack-surface-map.html` και `attack-surface-map.json`. Άνοιξε το HTML τοπικά στον browser: μπορείς να ψάξεις hosts, URLs, τεχνολογίες, login panels και findings, να κάνεις zoom και να ακολουθήσεις τις σχέσεις τους. Ο χάρτης διαβάζει μόνο τα αρχεία αποτελεσμάτων αυτής της εκτέλεσης και δεν στέλνει νέα αιτήματα. Το `report.html` έχει επίσης σύνδεσμο προς τον χάρτη. Για να μη δημιουργηθεί χάρτης, χρησιμοποίησε `--no-attack-map`.

## 10. Προαιρετικό endpoint crawl με Katana

Το Katana είναι απενεργοποιημένο εκ προεπιλογής, επειδή κάνει επιπλέον HTTP requests για να ακολουθήσει links. Η τρέχουσα έκδοση upstream απαιτεί Go 1.26+ για εγκατάσταση· το TriageFlow ορίζει `CGO_ENABLED=1` κατά την προσπάθεια εγκατάστασης. Ενεργοποίησέ το μόνο σε δικά σου συστήματα ή ρητά εγκεκριμένο scope:

```bash
python3 triageflow.py -u https://example.com --crawl-endpoints
```

Προεπιλογές: βάθος 2, έως 5 requests/δευτερόλεπτο, διάρκεια 30 δευτερόλεπτα ανά target. Μπορείς να αλλάξεις τις ρυθμίσεις μέσα στα όρια της εφαρμογής:

```bash
python3 triageflow.py -u https://example.com --crawl-endpoints --crawl-depth 3 --crawl-rate 5 --crawl-duration 1m
```

Το βάθος επιτρέπεται από 1 έως 5, ο ρυθμός από 1 έως 50 requests/δευτερόλεπτο και η διάρκεια από 5 δευτερόλεπτα έως 5 λεπτά. Τα αποτελέσματα αποθηκεύονται στα `katana-findings.jsonl` και `katana.log`. Δεν υποβάλλονται credentials και δεν γίνεται αυτόματο login.
