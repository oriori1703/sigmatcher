from pathlib import Path

import pytest

from sigmatcher.results import Class, Export, Field, MatchedClass, MatchedExport, MatchedField, MatchedMethod, Method


@pytest.fixture
def sample_matched_class(tmp_path: Path) -> MatchedClass:
    smali_file = tmp_path / "NewSample.smali"
    _ = smali_file.write_text(".class public Lcom/example/NewSample;\n")

    return MatchedClass(
        original=Class(name="OriginalSample", package="com.example.old"),
        new=Class(name="NewSample", package="com.example"),
        matched_methods=[
            MatchedMethod(
                original=Method(name="doWork", argument_types="Ljava/lang/String;", return_type="V"),
                new=Method(name="a", argument_types="Ljava/lang/String;", return_type="V"),
            )
        ],
        matched_fields=[
            MatchedField(
                original=Field(name="counter", type="I"),
                new=Field(name="b", type="I"),
            )
        ],
        exports=[MatchedExport(new=Export(name="exportA", value="VALUE_A"))],
        smali_file=smali_file,
    )
