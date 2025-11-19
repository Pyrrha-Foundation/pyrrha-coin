// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PYRRHA_QT_PYRRHAADDRESSVALIDATOR_H
#define PYRRHA_QT_PYRRHAADDRESSVALIDATOR_H

#include <QValidator>

/**
 * Address entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class BitcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressEntryValidator(const std::string &cashaddrprefix, QObject *parent);

    State validate(QString &input, int &pos) const;

private:
    std::string cashaddrprefix;
};

/** Address widget validator, checks for a valid address.
 */
class BitcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // PYRRHA_QT_PYRRHAADDRESSVALIDATOR_H
