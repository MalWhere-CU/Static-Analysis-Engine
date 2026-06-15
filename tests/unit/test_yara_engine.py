import pytest
import yara


@pytest.mark.unit
class TestEngineConstruction:

    def test_valid_rule_compiles(self, sample_yara_rule):
        from yara_engine.engine import YaraEngine
        eng = YaraEngine(sample_yara_rule)
        assert eng.rules is not None

    def test_blank_string_rejected(self):
        from yara_engine.engine import YaraEngine
        with pytest.raises(ValueError, match="No YARA rules"):
            YaraEngine("")

    def test_whitespace_only_rejected(self):
        from yara_engine.engine import YaraEngine
        with pytest.raises(ValueError, match="No YARA rules"):
            YaraEngine("   \n\t  ")

    def test_broken_syntax_rejected(self):
        from yara_engine.engine import YaraEngine
        with pytest.raises(yara.SyntaxError):
            YaraEngine("rule invalid { condition: }")

    def test_externals_keys_present(self, sample_yara_rule):
        from yara_engine.engine import YaraEngine
        eng = YaraEngine(sample_yara_rule)
        for key in ("extension", "filename", "filepath", "filetype", "owner"):
            assert key in eng.externals

    def test_concatenated_rules(self, sample_yara_rule, sample_yara_rule_2):
        from yara_engine.engine import YaraEngine
        eng = YaraEngine(sample_yara_rule + "\n" + sample_yara_rule_2)
        assert eng.rules is not None


@pytest.mark.unit
class TestEngineScan:

    def test_returns_iterable(self, sample_yara_rule, sample_pe_file):
        from yara_engine.engine import YaraEngine
        eng = YaraEngine(sample_yara_rule)
        assert isinstance(eng.scan_file(sample_pe_file), list)

    def test_scan_does_not_crash(self, sample_yara_rule, sample_pe_file):
        from yara_engine.engine import YaraEngine
        eng = YaraEngine(sample_yara_rule)
        # just verify it runs without exception
        eng.scan_file(sample_pe_file)
