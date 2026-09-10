"""Validación de identificadores y utilidades de catálogo."""

import pytest

from fee_server.domain.osint.catalog import is_valid_identifier, split_phone


@pytest.mark.parametrize(
    "name",
    ["Ada Lovelace", "José Ñoño-Pérez", "O'Brien", "Jean-Luc Picard", "Zoe"],
)
def test_name_accepts_full_names_with_spaces_and_accents(name):
    assert is_valid_identifier("name", name)


@pytest.mark.parametrize(
    "name",
    ["a", "  ", "Ada  2", "user_name", "", "1Ada", "-Ada"],
)
def test_name_rejects_short_blank_or_digit_shaped_values(name):
    assert not is_valid_identifier("name", name)


@pytest.mark.parametrize("phone", ["+34611223344", "+14155552671", "+442071838750"])
def test_phone_accepts_e164(phone):
    assert is_valid_identifier("phone", phone)


@pytest.mark.parametrize("phone", ["611223344", "+0611223344", "+34 611 223 344", "+abc", "+3"])
def test_phone_rejects_non_e164(phone):
    assert not is_valid_identifier("phone", phone)


def test_unknown_target_type_is_invalid():
    assert not is_valid_identifier("telefono", "+34611223344")


def test_split_phone_divides_country_and_national_number():
    assert split_phone("+34611223344") == ("34", "611223344")
    assert split_phone("+14155552671") == ("1", "4155552671")


def test_split_phone_rejects_an_invalid_number():
    with pytest.raises(ValueError):
        split_phone("+9999999999999")
