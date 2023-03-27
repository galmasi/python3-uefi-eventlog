all: pylint-test pyright-test comparison validation

pylint-test:
	@echo "Running a pylint test"
	@pylint --rcfile pylintrc eventlog/eventlog.py


pyright-test:
	@echo "Type checking"
	@pyright

comparison:
	@./testing/test_compare.py -d testlogs


validation:
	@./testing/test_validate.py -d testlogs
