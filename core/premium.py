import os
import re
from typing import List, Dict, Optional, Tuple, Set
from .utils import setup_logger, Color, SmaliHelper


class PremiumAnalyzer:
    def __init__(self, analyzer, logger=None):
        self.analyzer = analyzer
        self.logger = logger or setup_logger()
        self.findings = {
            'subscription_methods': [],
            'billing_integrations': [],
            'third_party_payment': [],
            'premium_booleans': [],
            'premium_checks': [],
            'server_validation': [],
            'paywall_classes': [],
            'obfuscated_billing': [],
            'feature_flags': [],
            'license_checks': [],
        }

        self.KEYWORDS = [
            'isPremium', 'isSubscribed', 'isPro', 'isVip', 'isPaid', 'isPurchased',
            'hasActiveSubscription', 'hasSubscription', 'hasPremium', 'hasPro',
            'isUnlocked', 'isUnlock', 'unlockPremium', 'unlockPro',
            'isTrial', 'trialActive', 'trialExpired', 'isTrialAvailable',
            'validateLicense', 'checkLicense', 'verifyLicense',
            'subscriptionStatus', 'subscriptionExpiry', 'subscriptionEnd',
            'purchaseToken', 'orderId', 'paymentConfirmed',
            'productId', 'skuDetails', 'purchaseData',
            'billingResponse', 'BillingResult', 'purchasesList',
            'queryPurchases', 'querySkuDetails', 'launchBillingFlow',
            'consumePurchase', 'acknowledgePurchase',
            'premiumFeatures', 'premiumOnly', 'vipOnly',
            'licenseStatus', 'LICENSE_STATUS', 'LICENSED',
            'premium_enabled', 'is_premium', 'is_subscribed',
            'getSubscription', 'getPremiumStatus',
            'canAccess', 'hasAccess', 'isEntitled',
            'pro_features', 'vip_features', 'gold_membership',
            'plus_enabled', 'pro_enabled', 'vip_enabled',
            'memberSince', 'subscriptionPlan', 'planType',
            'shouldShowAds', 'isAdsRemoved', 'adsRemoved',
            'subscription_active', 'subscriptionValid',
            'receiptValidation', 'validateReceipt', 'verifyReceipt',
            'restorePurchases', 'restoreTransactions',
        ]

        self.BILLING_CLASSES = [
            'com/android/billingclient', 'com/android/vending/billing',
            'com/revenuecat', 'com/adapty', 'com/qonversion',
            'com/purchasely', 'com/apphud',
        ]

    def analyze(self) -> Dict:
        self.logger.info(f"\n[*] Analyzing premium/subscription logic...")
        self._scan_for_keywords()
        self._scan_billing_integrations()
        self._scan_third_party_payment()
        self._scan_paywall_classes()
        self._scan_server_validation()
        self._scan_feature_flags()
        self._scan_license_checks()
        self._scan_obfuscated_billing()
        self._summarize()
        return self.findings

    def _scan_for_keywords(self):
        self.logger.info(f"    Scanning for {len(self.KEYWORDS)} subscription keywords...")
        found_kws = set()
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for kw in self.KEYWORDS:
                    if kw in content:
                        pattern = kw.lower().replace('_', '').replace('is', '').replace('has', '').replace('get', '')
                        entry = {'keyword': kw, 'file': rel_path}
                        if entry not in self.findings['premium_checks'] and kw.lower() not in found_kws:
                            found_kws.add(kw.lower())
                            self.findings['premium_checks'].append(entry)

                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if kw in line and '.method' not in line:
                                method_ctx = self._find_enclosing_method(lines, i)
                                method_entry = {
                                    'keyword': kw,
                                    'file': rel_path,
                                    'line': i + 1,
                                    'method': method_ctx or 'unknown',
                                    'code': line.strip()
                                }
                                if method_entry not in self.findings['subscription_methods']:
                                    self.findings['subscription_methods'].append(method_entry)
                            if kw in line and '.method' in line and 'Z' in line.split(')')[-1] if ')' in line else False:
                                bool_entry = {
                                    'keyword': kw,
                                    'file': rel_path,
                                    'line': i + 1,
                                    'method_line': line.strip()
                                }
                                if bool_entry not in self.findings['premium_booleans']:
                                    self.findings['premium_booleans'].append(bool_entry)
            except Exception:
                pass

        if self.findings['premium_booleans']:
            self.logger.info(f"      Premium boolean methods: {len(self.findings['premium_booleans'])}")
        if self.findings['premium_checks']:
            self.logger.info(f"      Premium checks found: {len(self.findings['premium_checks'])}")

    def _scan_billing_integrations(self):
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for bc in self.BILLING_CLASSES:
                    if bc in content:
                        entry = {'billing_class': bc, 'file': rel_path}
                        if entry not in self.findings['billing_integrations']:
                            self.findings['billing_integrations'].append(entry)
            except Exception:
                pass

        for billing_ref, _ in self.analyzer.billing_imports:
            found = False
            for entry in self.findings['billing_integrations']:
                if billing_ref == entry.get('file'):
                    found = True
                    break
            if not found:
                self.findings['billing_integrations'].append({
                    'billing_class': 'billing_reference',
                    'file': billing_ref
                })

        if self.findings['billing_integrations']:
            self.logger.info(f"      Billing integrations: {len(self.findings['billing_integrations'])}")

    def _scan_third_party_payment(self):
        third_party_detectors = {
            'RevenueCat': ['com/revenuecat', 'RevenueCat', 'Purchases', 'RCConfiguration'],
            'Adapty': ['com/adapty', 'Adapty', 'AdaptyUI'],
            'Qonversion': ['com/qonversion', 'Qonversion', 'QLaunchResult'],
            'Purchasely': ['com/purchasely', 'Purchasely', 'PurchaselyPlugin'],
            'Apphud': ['com/apphud', 'Apphud', 'ApphudSubscription'],
        }
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for name, signatures in third_party_detectors.items():
                    for sig in signatures:
                        if sig in content:
                            entry = {'service': name, 'file': rel_path}
                            if entry not in self.findings['third_party_payment']:
                                self.findings['third_party_payment'].append(entry)
                                self.logger.info(f"      [PAYMENT] {name} found in {rel_path}")
                            break
            except Exception:
                pass

    def _scan_paywall_classes(self):
        paywall_indicators = [
            'Paywall', 'paywall', 'PAYWALL',
            'SubscriptionActivity', 'PurchaseActivity',
            'BillingActivity', 'InAppPurchase',
            'UpgradeActivity', 'PremiumActivity',
            'ProActivity', 'VipActivity',
            'CheckoutActivity', 'ShopActivity',
            'StoreActivity', 'PaymentActivity',
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                fname = os.path.basename(smali_file)
                for pi in paywall_indicators:
                    if pi.lower() in fname.lower() or pi.lower() in content.lower():
                        entry = {'indicator': pi, 'file': rel_path}
                        if entry not in self.findings['paywall_classes']:
                            self.findings['paywall_classes'].append(entry)
                            self.logger.info(f"      [PAYWALL] {pi} in {rel_path}")
                        break
            except Exception:
                pass

    def _scan_server_validation(self):
        validation_patterns = [
            (r'https?://[^"\']*(?:validate|verify|receipt|purchase|subscription|license|iap)[^"\']*', 'Server validation endpoint'),
            (r'HTTP\.(?:POST|GET|PUT).*?(?:validate|verify|receipt)', 'HTTP validation call'),
            (r'URLConnection.*?(?:validate|verify)', 'URL validation connection'),
            (r'okhttp3?.*?(?:validate|verify|receipt)', 'OkHTTP validation'),
            (r'\{.*?"receipt".*?"\}', 'Receipt data in request'),
            (r'\{.*?"purchaseToken".*?"\}', 'Purchase token in request'),
            (r'\{.*?"productId".*?"\}', 'Product ID in request'),
            (r'\{.*?"developerPayload".*?"\}', 'Developer payload'),
            (r'responseCode.*?0\s*[=!]=?\s*0', 'Response code check'),
            (r'isSuccess|isValid|getStatus.*?0', 'Success status check'),
            (r'"status".*?200|"success".*?true', 'Success response check'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in validation_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        entry = {'description': desc, 'file': rel_path}
                        if entry not in self.findings['server_validation']:
                            self.findings['server_validation'].append(entry)
            except Exception:
                pass
        if self.findings['server_validation']:
            self.logger.info(f"      Server validation points: {len(self.findings['server_validation'])}")

    def _scan_feature_flags(self):
        flag_patterns = [
            r'premium_(enabled|active|unlocked)',
            r'pro_(enabled|active|unlocked)',
            r'vip_(enabled|active|unlocked)',
            r'is_premium',
            r'is_pro',
            r'is_vip',
            r'is_paid',
            r'has_premium',
            r'has_pro',
            r'has_unlocked',
            r'subscription_active',
            r'premiumFeatures',
            r'feature_(\w+)_enabled',
            r'flag_premium',
            r'isFeatureEnabled',
            r'isFeatureAvailable',
            r'featureToggle',
            r'experiment_enabled',
            r'billing_ready',
            r'onboarding_complete',
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat in flag_patterns:
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        entry = {'flag': m.group(), 'file': rel_path}
                        if entry not in self.findings['feature_flags']:
                            self.findings['feature_flags'].append(entry)
            except Exception:
                pass

    def _scan_license_checks(self):
        license_patterns = [
            r'LicenseChecker',
            r'LicenseValidator',
            r'Policy\.LICENSED',
            r'Policy\.NOT_LICENSED',
            r'allowAccess',
            r'isLicensed',
            r'checkLicense',
            r'verifyLicense',
            r'LICENSE_STATUS',
            r'SERVER_URL',
            r'getWLock',
            r'validateLicense',
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat in license_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        entry = {'pattern': pat, 'file': rel_path}
                        if entry not in self.findings['license_checks']:
                            self.findings['license_checks'].append(entry)
                            self.logger.info(f"      [LICENSE] {pat} in {rel_path}")
            except Exception:
                pass

    def _scan_obfuscated_billing(self):
        obfuscation_indicators = [
            'billing', 'Billing', 'BILLING',
            'purchase', 'Purchase', 'PURCHASE',
            'subscription', 'Subscription', 'SUBSCRIPTION',
            'premium', 'Premium', 'PREMIUM',
            'receipt', 'Receipt', 'RECEIPT',
        ]
        for smali_file in self.analyzer.all_smali_files:
            rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
            dir_parts = rel_path.replace('\\', '/').split('/')
            if len(dir_parts) >= 2 and dir_parts[-2] in ['a', 'b', 'c', 'aa', 'ab', 'ac']:
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    for oi in obfuscation_indicators:
                        if oi in content:
                            entry = {'file': rel_path, 'indicator': oi}
                            if entry not in self.findings['obfuscated_billing']:
                                self.findings['obfuscated_billing'].append(entry)
                            break
                except Exception:
                    pass

    def _find_enclosing_method(self, lines: List[str], line_no: int) -> Optional[str]:
        for i in range(line_no, -1, -1):
            if '.method ' in lines[i]:
                return lines[i].strip()
        return None

    def _summarize(self):
        total = sum(len(v) for v in self.findings.values())
        if total > 0:
            self.logger.info(f"      Total premium/subscription findings: {total}")
        else:
            self.logger.info(f"      No premium/subscription logic detected")

    def has_premium(self) -> bool:
        return bool(
            self.findings['premium_booleans'] or
            self.findings['billing_integrations'] or
            self.findings['third_party_payment'] or
            self.findings['paywall_classes'] or
            self.findings['subscription_methods']
        )


class PremiumPatcher:
    def __init__(self, analyzer, findings: Dict, logger=None):
        self.analyzer = analyzer
        self.findings = findings
        self.logger = logger or setup_logger()
        self.patches_applied = []

    def patch_all(self) -> bool:
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"[*] Applying premium/subscription bypass patches...")
        self.logger.info(f"{'=' * 60}")

        patched = False
        patched |= self._patch_premium_booleans()
        patched |= self._patch_billing_checks()
        patched |= self._patch_server_validation()
        patched |= self._patch_feature_flags()
        patched |= self._patch_license_checks()
        patched |= self._patch_third_party_payment()
        patched |= self._patch_paywall_methods()

        if patched:
            self.logger.info(f"[+] Premium bypass complete - {len(self.patches_applied)} patches applied")
        else:
            if self.findings.get('premium_booleans') or self.findings.get('billing_integrations'):
                self.logger.warning("[-] Premium detected but patching may be incomplete")
            else:
                self.logger.info("[-] No premium logic to patch")
        return patched

    def _patch_premium_booleans(self) -> bool:
        patched = False
        for entry in self.findings['premium_booleans']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                method_name_match = re.match(
                    r'\.method\s+(?:public|private|protected|static|final)?\s*(\w+)',
                    entry['method_line']
                )
                if not method_name_match:
                    continue
                method_name = method_name_match.group(1)

                method_body = SmaliHelper.extract_method_body(content, method_name)
                if method_body:
                    new_body = SmaliHelper.make_method_return_true(method_body)
                    new_content = content.replace(method_body, new_body)
                    if new_content != content:
                        with open(smali_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        self.patches_applied.append({
                            'type': 'premium_bool',
                            'description': f'Patched {method_name}() to return true',
                            'target': f"{entry['file']}:{entry['line']}"
                        })
                        self.logger.info(f"  [+] Patched boolean: {method_name}() -> true in {entry['file']}")
                        patched = True
            except Exception as e:
                self.logger.debug(f"    Error patching boolean in {entry['file']}: {e}")

        for entry in self.findings['subscription_methods']:
            kw = entry['keyword']
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                modified = False
                if entry['method']:
                    method_first_line = entry['method'].strip()
                    if 'Z' in method_first_line.split(')')[-1] if ')' in method_first_line else '':
                        method_name_m = re.match(r'\.method\s+(?:public|private|protected|static|final)?\s*(\w+)', method_first_line)
                        if method_name_m:
                            mn = method_name_m.group(1)
                            method_body = SmaliHelper.extract_method_body(content, mn)
                            if method_body:
                                new_body = SmaliHelper.make_method_return_true(method_body)
                                new_content = content.replace(method_body, new_body)
                                if new_content != content:
                                    content = new_content
                                    modified = True
                                    self.logger.info(f"  [+] Patched subscription method: {mn}() in {entry['file']}")
                                    self.patches_applied.append({
                                        'type': 'subscription_method',
                                        'description': f'Patched {mn}() to return true',
                                        'target': f"{entry['file']}:{entry['line']}"
                                    })
                                    patched = True
                if modified:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
            except Exception:
                pass

        return patched

    def _patch_billing_checks(self) -> bool:
        patched = False
        for entry in self.findings['billing_integrations']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                content = re.sub(
                    r'\.method\s+.*\bqueryPurchases\b.*?\)V\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 2\n    const/4 v0, 0x0\n    return-void\n.end method',
                    content, flags=re.DOTALL
                )
                content = re.sub(
                    r'\.method\s+.*\bquerySkuDetailsAsync\b.*?\)V\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 2\n    const/4 v0, 0x0\n    return-void\n.end method',
                    content, flags=re.DOTALL
                )
                content = re.sub(
                    r'\.method\s+.*\blaunchBillingFlow\b.*?\)Z\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method',
                    content, flags=re.DOTALL
                )
                content = re.sub(
                    r'\.method\s+.*\bqueryPurchaseHistoryAsync\b.*?\)V\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 2\n    const/4 v0, 0x0\n    return-void\n.end method',
                    content, flags=re.DOTALL
                )
                content = re.sub(
                    r'\.method\s+.*\b(?:acknowledgePurchase|consumeAsync)\b.*?\)V\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 2\n    const/4 v0, 0x0\n    return-void\n.end method',
                    content, flags=re.DOTALL
                )

                content = re.sub(
                    r'iget\s+\w+,\s+\w+,\s*L.*?;->(mIsPremium|mIsSubscribed|mIsPro|mIsVip|mIsUnlocked|mHasSubscription):Z',
                    'const/4 v0, 0x1\niput v0, \1',
                    content
                )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.info(f"  [+] Patched billing methods in {entry['file']}")
                    self.patches_applied.append({
                        'type': 'billing_patch',
                        'description': 'NOP\'d billing methods and force premium fields',
                        'target': entry['file']
                    })
                    patched = True
            except Exception as e:
                self.logger.debug(f"    Error patching billing in {entry['file']}: {e}")

        return patched

    def _patch_server_validation(self) -> bool:
        patched = False
        for entry in self.findings['server_validation']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                content = re.sub(
                    r'\.method\s+.*\b(validate|verify|check)(Receipt|Purchase|Subscription|License)\b.*?\)Z\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method',
                    content, flags=re.DOTALL | re.IGNORECASE
                )

                content = re.sub(
                    r'\.method\s+.*\b(validate|verify|check)(Receipt|Purchase|Subscription|License)\b.*?\)I\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method',
                    content, flags=re.DOTALL | re.IGNORECASE
                )

                content = re.sub(
                    r'iget\s+\w+,\s+\w+,\s*L.*?;(responseCode|purchaseState|verificationStatus):I',
                    'const/4 v1, 0x0\niput v1, v0, L $1:I',
                    content
                )

                if 'BillingResult' in content or 'billingResult' in content:
                    content = re.sub(
                        r'const/4\s+\w+,\s*(-?0x[0-9a-f]+|\d+)\s*#\s*(error|failure|denied|rejected)',
                        'const/4 v0, 0x0',
                        content
                    )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.info(f"  [+] Patched server validation in {entry['file']}")
                    self.patches_applied.append({
                        'type': 'server_validation',
                        'description': 'Patched server validation to return success',
                        'target': entry['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _patch_feature_flags(self) -> bool:
        patched = False
        visited = set()
        for entry in self.findings['feature_flags']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if smali_path in visited:
                continue
            visited.add(smali_path)
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content
                flag = entry['flag']

                uses_boolean = re.findall(
                    rf'\.method\s+.*\b{re.escape(flag)}\b.*?\)Z\s*\n.*?\.end\s+method',
                    content, re.DOTALL
                )
                for m in uses_boolean:
                    start = m.index('.method')
                    body = m[start:]
                    new_body = body.split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'
                    content = content.replace(body, new_body)
                    self.logger.info(f"  [+] Patched feature flag boolean: {flag} in {entry['file']}")
                    patched = True

                const_string_flags = re.findall(
                    rf'const-string\s+\w+,\s*"{re.escape(flag)}"',
                    content
                )
                for cs in const_string_flags:
                    content = content.replace(cs, cs.replace(flag, f'{flag}_enabled'))

                sget_flags = re.findall(
                    rf'sget-(?:boolean|object)\s+\w+,\s*L.*?;{re.escape(flag)}:Z',
                    content
                )
                for sf in sget_flags:
                    reg = re.search(r'sget-(?:boolean|object)\s+(\w+),', sf)
                    if reg:
                        reg_name = reg.group(1)
                        content = content.replace(sf, f'const/4 {reg_name}, 0x1')

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'feature_flag',
                        'description': f'Patched {flag} to enabled',
                        'target': entry['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _patch_license_checks(self) -> bool:
        patched = False
        for entry in self.findings['license_checks']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                license_methods = re.findall(
                    r'\.method\s+.*(?:allowAccess|isLicensed|checkLicense|verifyLicense|validateLicense)\b.*?\)Z\s*\n.*?\.end\s+method',
                    content, re.DOTALL | re.IGNORECASE
                )
                for lm in license_methods:
                    new_body = lm.split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'
                    content = content.replace(lm, new_body)
                    self.logger.info(f"  [+] Patched license check in {entry['file']}")
                    patched = True

                content = re.sub(
                    r'sget\s+\w+,\s*L.*?;->LICENSE_STATUS:I',
                    'const/4 v0, 0x0\nsput v0, L...;->LICENSE_STATUS:I',
                    content
                )
                content = re.sub(
                    r'const-string\s+\w+,\s*"(?:NOT_)?LICENSED"',
                    'const-string v0, "LICENSED"',
                    content
                )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'license_patch',
                        'description': 'Patched license check to return LICENSED',
                        'target': entry['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _patch_third_party_payment(self) -> bool:
        patches = {
            'RevenueCat': [
                (r'Lcom/revenuecat/purchases/Purchases;->getAppUserID\(\)Ljava/lang/String;',
                 'const-string v0, "patched_user_id"'),
                (r'Lcom/revenuecat/purchases/Purchases;->getOfferings\(.*?\)V',
                 'return-void'),
                (r'\.method\s+.*\b(?:isEntitled|checkTrialOrIntroductoryPrice|getSubscriptionStatus)\b.*?\)Z\s*\n.*?\.end\s+method',
                 lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'),
            ],
            'Adapty': [
                (r'\.method\s+.*\b(?:getPaidAccessLevel|getSubscriptionInfo|validateReceipt)\b.*?\)Z\s*\n.*?\.end\s+method',
                 lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'),
            ],
            'Qonversion': [
                (r'\.method\s+.*\b(?:isEntitled|checkPermissions|getUserPermissions)\b.*?\)Z\s*\n.*?\.end\s+method',
                 lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'),
            ],
        }
        patched = False
        for entry in self.findings['third_party_payment']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            service = entry['service']
            if service not in patches:
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content
                for pat, repl in patches[service]:
                    if isinstance(repl, str):
                        content = re.sub(pat, repl, content, flags=re.DOTALL | re.IGNORECASE)
                    else:
                        content = re.sub(pat, repl, content, flags=re.DOTALL | re.IGNORECASE)
                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.info(f"  [+] Patched {service} in {entry['file']}")
                    self.patches_applied.append({
                        'type': 'third_party_payment',
                        'description': f'Patched {service} to return premium status',
                        'target': entry['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _patch_paywall_methods(self) -> bool:
        patched = False
        for entry in self.findings['paywall_classes']:
            smali_path = os.path.join(self.analyzer.decompile_dir, entry['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                onCreateMatches = re.findall(
                    r'\.method\s+.*\bonCreate\b.*?\)V\s*\n.*?\.end\s+method',
                    content, re.DOTALL
                )
                for m in onCreateMatches:
                    new_body = m.split('\n')[0] + '\n    .locals 1\n    invoke-super {p0}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n    return-void\n.end method'
                    content = content.replace(m, new_body)
                    self.logger.info(f"  [+] NOP'd paywall activity: {entry['file']}")
                    patched = True

                indicator = entry.get('indicator', '')
                class_match = re.search(
                    r'\.class\s+.*\s+' + re.escape(indicator) + r'\s*',
                    content
                )
                if not class_match:
                    class_match = re.search(
                        r'\.class\s+.*\s+\w*' + re.escape(indicator) + r'\w*\s*',
                        content
                    )
                if class_match:
                    class_line = class_match.group(0)
                    if 'Activity' not in class_line and 'AppCompatActivity' not in class_line:
                        content = content.replace(
                            class_line,
                            class_line.rstrip() + ' Landroid/app/Activity;'
                        )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'paywall_nop',
                        'description': f'NOP\'d paywall/subs activity {entry.get("indicator", "")}',
                        'target': entry['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched
