"""
Scenario: You need to design a reporting layer for an enterprise pipeline. 
It must support multiple output formats (HTML, JSON, and Slack notifications) 
dynamically based on what the user passes to the CLI commands.

How would you structure this using Python Object-Oriented Programming (OOP) 
and Design Patterns (e.g., Factory or Strategy patterns) to ensure adding a new report 
type in the future requires zero modifications to your existing test runner engine?

"""

from abc import ABC, abstractmethod

#any class that inherits from this must implement the generate method, 
# otherwise it will throw
class BaseReport(ABC):  
    @abstractmethod
    def generate(self, data):
        pass  # Subclasses will overwrite this


class HTMLReport(BaseReport):
    def generate(self, data):
        return f"<html>{data}</html>"


class JSONReport(BaseReport):
    def generate(self, data):
        return f"{{ 'data': {data} }}"


class SlackReport(BaseReport):
    def generate(self, data):
        return f"Slack Alert: {data}"


#The purpose of the ReportFactory is to abstract away object creation logic. 
# It takes a simple string argument from the CLI and dynamically instantiates 
# the correct object. This completely decouples our main test engine from
#  the specific report subclasses, keeping our architecture compliant
#  with the Open/Closed Principle and providing a centralized fallback strategy."
class ReportFactory:
    @staticmethod
    def get_reporter(format_type):
        mapping = {
            "html": HTMLReport,
            "json": JSONReport,
            "slack": SlackReport
        }
        # Fallback to JSON if the user types an invalid format
        return mapping.get(format_type.lower(), JSONReport)()

class TestRunner:
    def __init__(self, cli_format):
        # Factory instantly gives us the correct object instance
        self.reporter = ReportFactory.get_reporter(cli_format)

    def run_tests(self):
        test_results = "Pass: 95, Fail: 5"
        
        # Polymorphism in action: it just works
        final_output = self.reporter.generate(test_results)
        # publish_output = self.reporter.publish(test_results)
        print(final_output)

# Simulating running: python main.py --format slack
runner = TestRunner(cli_format="slack")
runner.run_tests()  # Outputs: Slack Alert: Pass: 95, Fail: 5
