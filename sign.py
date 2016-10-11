# -*- coding: utf-8 -*- 
import argparse
import base64
import subprocess
import uuid
from datetime import datetime

import pytz
from lxml import etree as ET


def parse_args():
    """
    Парсим аргументы командной строки
    """
    parser = argparse.ArgumentParser(description='XAdES-BES signer')
    parser.add_argument('keyfile', help='Key file for sign')
    parser.add_argument('xmlfile', help='XML file for sign')
    parser.add_argument('id', help='ID of signed element')
    return parser.parse_args()


def run(cmd, input=None):
    """
    Запуск субпроцесса
    """
    pr = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return pr.communicate(input=input)


def get_digest(text):
    """
    Дайджест
    """
    cmd = ['openssl', 'dgst', '-binary', '-md_gost94']
    out, err = run(cmd, input=text)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)
    return base64.b64encode(out)


def get_issuer(private_key):
    """
    Issuer
    """
    cmd = ['openssl', 'x509', '-noout', '-issuer', '-nameopt', 'sep_multiline,utf8', '-in', private_key]
    out, err = run(cmd)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)
    issuer = out[9:]
    props = list(reversed(issuer.split('\n')))
    res = []
    for prop in props:
        props_ar = prop.split("=")
        if len(props_ar) > 1:
            prop_name = props_ar[0].lower().strip()
            prop_val = props_ar[1].replace('"', '\\"').replace(',', '\\,')
            res.append('%s=%s' % (prop_name, prop_val))
    return ','.join(res).replace('emailaddress', '1.2.840.113549.1.9.1')


def get_serial(private_key):
    """
    Serial
    """
    cmd = ['openssl', 'x509', '-noout', '-serial', '-in', private_key]
    out, err = run(cmd)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)
    return str(int(out.split('=')[1], 16))


def get_signature(text, private_key):
    """
    Подпись
    """
    cmd = ['openssl', 'dgst', '-sign', private_key, '-binary', '-md_gost94']
    out, err = run(cmd, input=text)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)
    return base64.b64encode(out)


def get_element(tree, el_path, namespaces):
    """
    Поиск элемента
    """
    return tree.xpath(el_path, namespaces=namespaces)[0]


def get_canonic(element, exc=False):
    """
    Канонизация
    """
    return ET.tostring(element, method='c14n', exclusive=exc)


def load_cert(key_file):
    """
    Загрузка сертификата
    """
    head = '-----BEGIN CERTIFICATE-----'
    tail = '-----END CERTIFICATE-----'

    with open(key_file) as f:
        key_data = f.read()

    key_data = key_data.replace('\r', '').replace('\n', '')
    cert_start = key_data.find(head)
    cert_end = key_data.find(tail)

    return key_data[cert_start + len(head):cert_end]


def main():
    """
    Основная программа
    """
    args = parse_args()

    xades_template_file = './xades.xml'

    in_file = args.xmlfile
    key_file = args.keyfile

    nsmap = dict(ds='http://www.w3.org/2000/09/xmldsig#')

    # Парсим XML
    tree = ET.parse(in_file)

    # Получаем все namespaces
    for ns in tree.xpath('//namespace::*'):
        if ns[0]:
            nsmap[ns[0]] = ns[1]

    # подготавливаем данные для вставки в шаблон XAdES
    sign_data = dict(
        signed_id=args.id,
        signature_id=uuid.uuid1(),
        signing_time=datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).isoformat(),
        x509_issuer_name=get_issuer(key_file),
        x509_sn=get_serial(key_file)
    )

    # элемент для подписи
    signing_el = get_element(tree, '//*[@Id="%s"]' % sign_data['signed_id'], nsmap)
    signing_el_canonic = get_canonic(signing_el, exc=True)

    # первый digest
    sign_data['digest1'] = get_digest(signing_el_canonic)

    # x509 ключ из файла
    sign_data['x590_cert'] = load_cert(key_file)

    # второй digest
    sign_data['digest2'] = get_digest(base64.b64decode(sign_data['x590_cert']))

    # формируем xades
    with open(xades_template_file) as f:
        data = f.read()
    sign_data['digest3'] = ''
    sign_data['signature_value'] = ''
    xades = data.format(**sign_data)

    # подмешиваем xades в xml
    signing_el.insert(0, ET.fromstring(xades))

    # третий digest
    path = '//*[@Id="xmldsig-%s-signedprops"]' % sign_data['signature_id']
    signed_props = get_element(tree, path, nsmap)
    signed_props_canonic = get_canonic(signed_props, exc=False)
    digest3 = get_digest(signed_props_canonic)
    path = '//ds:SignedInfo/ds:Reference[@URI="#xmldsig-%s-signedprops"]/ds:DigestValue' % sign_data['signature_id']
    el = get_element(tree, path, nsmap)
    el.text = digest3

    # подпись
    path = '//ds:SignedInfo'
    signed_info = get_element(tree, path, nsmap)
    signed_info_canonic = get_canonic(signed_info, exc=False)
    signature = get_signature(signed_info_canonic, key_file)
    path = '//ds:SignatureValue'
    el = get_element(tree, path, nsmap)
    el.text = signature

    return get_canonic(tree)


if __name__ == '__main__':
    print main()
