#!/usr/bin/env python3
"""
Test script to demonstrate the AgenticAccessGovernance system.
Processes access request REQ001 and prints the complete decision workflow.
"""

import json
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.crew import AccessGovernanceCrew
from src.db.iam_database import IAMDatabase

console = Console()

def load_test_request(request_id: str = "REQ001") -> dict:
    """Load a test access request from the data directory."""
    request_path = Path(f"data/requests/{request_id}.json")
    
    if not request_path.exists():
        raise FileNotFoundError(f"Test request {request_id} not found at {request_path}")
    
    with open(request_path, 'r') as f:
        return json.load(f)

def display_request_info(request_data: dict):
    """Display the access request information."""
    table = Table(title="Access Request Details", show_header=True)
    table.add_column("Field", style="bold blue")
    table.add_column("Value", style="green")
    
    table.add_row("Request ID", request_data["id"])
    table.add_row("User ID", request_data["user_id"])
    table.add_row("System", request_data["system_id"])
    table.add_row("Access Level", request_data["access_level"])
    table.add_row("Type", request_data["request_type"])
    table.add_row("Emergency", "Yes" if request_data.get("is_emergency", False) else "No")
    table.add_row("Requested Date", request_data["requested_date"])
    table.add_row("Required By", request_data.get("required_by_date", "Not specified"))
    
    console.print(table)
    console.print()
    
    # Display justification
    console.print(Panel(
        request_data["justification"],
        title="Business Justification",
        border_style="blue"
    ))
    console.print()

def display_decision_results(result: dict):
    """Display the governance decision results."""
    # Overall Decision
    decision = result.get("final_decision", "UNKNOWN")
    decision_color = {
        "APPROVED": "green",
        "DENIED": "red", 
        "ESCALATED": "yellow",
        "ERROR": "red"
    }.get(decision, "white")
    
    console.print(Panel(
        f"[bold {decision_color}]{decision}[/bold {decision_color}]",
        title="Final Decision",
        border_style=decision_color
    ))
    console.print()
    
    # Risk Assessment
    if "risk_analysis" in result:
        risk_data = result["risk_analysis"]
        risk_table = Table(title="Risk Assessment", show_header=True)
        risk_table.add_column("Component", style="bold")
        risk_table.add_column("Score", justify="center")
        risk_table.add_column("Details", style="dim")
        
        overall_score = risk_data.get("overall_risk_score", 0)
        risk_level = risk_data.get("risk_level", "UNKNOWN")
        
        risk_table.add_row(
            "Overall Risk", 
            f"[bold]{overall_score}[/bold]",
            f"Level: {risk_level}"
        )
        
        # Add component scores
        components = risk_data.get("risk_components", {})
        for component, score in components.items():
            risk_table.add_row(
                component.replace("_", " ").title(),
                str(score),
                ""
            )
        
        console.print(risk_table)
        console.print()
    
    # Policy Analysis
    if "policy_analysis" in result:
        policy_data = result["policy_analysis"]
        console.print(Panel(
            f"Decision: {policy_data.get('overall_decision', 'Unknown')}\n"
            f"Confidence: {policy_data.get('confidence_score', 0.0):.2%}\n"
            f"Violations: {len(policy_data.get('violation_reasons', []))}\n"
            f"Regulatory Flags: {len(policy_data.get('regulatory_flags', []))}",
            title="Policy Analysis Summary",
            border_style="cyan"
        ))
        console.print()
    
    # Decision Reasoning
    if "reasoning" in result:
        console.print(Panel(
            result["reasoning"],
            title="Decision Reasoning",
            border_style="magenta"
        ))
        console.print()
    
    # Next Steps
    if "next_steps" in result:
        next_steps = result["next_steps"]
        if isinstance(next_steps, list):
            steps_text = "\n".join(f"• {step}" for step in next_steps)
        else:
            steps_text = str(next_steps)
            
        console.print(Panel(
            steps_text,
            title="Next Steps",
            border_style="yellow"
        ))

async def main():
    """Main test function."""
    console.print(Panel(
        "[bold cyan]AgenticAccessGovernance System Test[/bold cyan]\n"
        "Processing access request REQ001 through the complete governance workflow",
        title="Test Runner",
        border_style="cyan"
    ))
    console.print()
    
    try:
        # Load test request
        console.print("[bold blue]Loading test request...[/bold blue]")
        request_data = load_test_request("REQ001")
        display_request_info(request_data)
        
        # Initialize database
        console.print("[bold blue]Initializing database...[/bold blue]")
        db = IAMDatabase()
        await db.initialize()
        console.print("[green]✓ Database initialized[/green]")
        console.print()
        
        # Initialize governance crew
        console.print("[bold blue]Initializing governance agents...[/bold blue]")
        crew = AccessGovernanceCrew()
        console.print("[green]✓ Agents initialized[/green]")
        console.print()
        
        # Process the request
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Processing access request through governance workflow...", total=None)
            
            result = await crew.process_access_request(request_data)
            
            progress.update(task, completed=100)
        
        console.print("[green]✓ Request processing complete[/green]")
        console.print()
        
        # Display results
        console.print("[bold blue]Governance Decision Results:[/bold blue]")
        console.print()
        display_decision_results(result)
        
        # Save results to output
        output_path = Path("output/test_result.json")
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        console.print(f"[dim]Full results saved to: {output_path}[/dim]")
        console.print()
        
        # Success message
        console.print(Panel(
            "[bold green]Test completed successfully![/bold green]\n\n"
            "The AgenticAccessGovernance system has processed REQ001 through the complete workflow:\n"
            "• Request intake and validation\n"
            "• Policy compliance checking\n" 
            "• Risk assessment and scoring\n"
            "• Approval routing decision\n"
            "• Audit trail logging\n"
            "• Certification verification",
            title="Test Results",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(Panel(
            f"[bold red]Error during test execution:[/bold red]\n\n{str(e)}",
            title="Test Failed",
            border_style="red"
        ))
        raise

if __name__ == "__main__":
    asyncio.run(main())