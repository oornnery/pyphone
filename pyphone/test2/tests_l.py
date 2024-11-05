#!/usr/bin/env python3
import socket
import time
import argparse
import uuid
import sys
import signal
from dataclasses import dataclass
from typing import Optional, List, Dict
import asyncio
from datetime import datetime
import statistics
import json
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    SpinnerColumn
)
from rich.panel import Panel
from rich.table import Table
import logging
from rich.theme import Theme

# Custom theme for Rich
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "success": "green",
})

console = Console(theme=custom_theme)

@dataclass
class SIPResponse:
    status_code: int
    status_message: str
    headers: dict
    raw_response: str
    response_time: float
    sequence: int

@dataclass
class SIPStats:
    packets_sent: int
    packets_received: int
    packets_lost: int
    min_time: float
    max_time: float
    avg_time: float
    median_time: float
    stddev_time: float
    loss_percentage: float
    status_codes: Dict[int, int]
    start_time: datetime
    end_time: datetime
    
    def to_dict(self):
        return {
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "packets_lost": self.packets_lost,
            "min_time_ms": round(self.min_time * 1000, 2),
            "max_time_ms": round(self.max_time * 1000, 2),
            "avg_time_ms": round(self.avg_time * 1000, 2),
            "median_time_ms": round(self.median_time * 1000, 2),
            "stddev_time_ms": round(self.stddev_time * 1000, 2),
            "loss_percentage": round(self.loss_percentage, 2),
            "status_codes": self.status_codes,
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S")
        }

class SIPOptionsTester:
    def __init__(self, host: str, port: int, count: int = 1, timeout: int = 3,
                 protocol: str = 'udp', interval: float = 1.0):
        self.host = host
        self.port = port
        self.count = count
        self.timeout = timeout
        self.protocol = protocol.lower()
        self.interval = interval
        self.logger = self._setup_logger()
        self.responses: List[Optional[SIPResponse]] = []
        self.interrupted = False
        self.start_time = None
        self.end_time = None
        self.progress = None
        
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.info("[yellow]Interrupted by user. Calculating statistics...[/yellow]")
        self.interrupted = True

    def _setup_logger(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, rich_tracebacks=True)]
        )
        return logging.getLogger("SIPOptionsTester")

    def _create_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console
        )

    def _generate_options_request(self, sequence: int) -> str:
        call_id = str(uuid.uuid4())
        branch = str(uuid.uuid4())[:24]
        local_ip = socket.gethostbyname(socket.gethostname())

        return (
            f"OPTIONS sip:{self.host}:{self.port} SIP/2.0\r\n"
            f"Via: SIP/2.0/{self.protocol.upper()} {local_ip}:5060"
            f";branch=z9hG4bK{branch}\r\n"
            f"From: sip:test@{local_ip};tag=123456\r\n"
            f"To: sip:{self.host}:{self.port}\r\n"
            f"Call-ID: {call_id}@{local_ip}\r\n"
            f"CSeq: {sequence} OPTIONS\r\n"
            f"Contact: <sip:test@{local_ip}:5060>\r\n"
            "Max-Forwards: 70\r\n"
            "User-Agent: Python-SIP-Tester\r\n"
            "Accept: application/sdp\r\n"
            "Content-Length: 0\r\n\r\n"
        )

    def _parse_response(self, response: str, response_time: float, sequence: int) -> SIPResponse:
        lines = response.split('\r\n')
        if not lines:
            raise ValueError("Empty SIP response")

        status_line = lines[0]
        try:
            _, status_code, *status_message = status_line.split(' ')
            status_code = int(status_code)
            status_message = ' '.join(status_message)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid status line format: {status_line}")

        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        return SIPResponse(
            status_code=status_code,
            status_message=status_message,
            headers=headers,
            raw_response=response,
            response_time=response_time,
            sequence=sequence
        )

    def create_stats_table(self, stats: SIPStats) -> Table:
        table = Table(title="SIP OPTIONS Test Statistics", show_header=True, header_style="bold magenta")
        
        # Add columns
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="green")
        
        # Add rows
        table.add_row("Duration", f"{(stats.end_time - stats.start_time).total_seconds():.1f} seconds")
        table.add_row("Packets Sent", str(stats.packets_sent))
        table.add_row("Packets Received", str(stats.packets_received))
        table.add_row("Packets Lost", f"{stats.packets_lost} ({stats.loss_percentage:.1f}%)")
        
        if stats.packets_received > 0:
            table.add_row("Min Response Time", f"{stats.min_time * 1000:.2f} ms")
            table.add_row("Max Response Time", f"{stats.max_time * 1000:.2f} ms")
            table.add_row("Average Response Time", f"{stats.avg_time * 1000:.2f} ms")
            table.add_row("Median Response Time", f"{stats.median_time * 1000:.2f} ms")
            table.add_row("Response Time Std Dev", f"{stats.stddev_time * 1000:.2f} ms")
        
        return table

    def create_status_codes_table(self, stats: SIPStats) -> Table:
        table = Table(title="Status Codes Distribution", show_header=True, header_style="bold magenta")
        
        table.add_column("Status Code", style="cyan")
        table.add_column("Count", justify="right", style="green")
        table.add_column("Percentage", justify="right", style="yellow")
        
        for status_code, count in stats.status_codes.items():
            percentage = (count / stats.packets_received) * 100
            table.add_row(
                str(status_code),
                str(count),
                f"{percentage:.1f}%"
            )
            
        return table

    def calculate_statistics(self) -> SIPStats:
        response_times = [r.response_time for r in self.responses if r is not None]
        status_codes = {}
        
        for response in self.responses:
            if response is not None:
                status_codes[response.status_code] = status_codes.get(response.status_code, 0) + 1
        
        packets_received = len(response_times)
        packets_sent = len(self.responses)
        packets_lost = packets_sent - packets_received
        
        return SIPStats(
            packets_sent=packets_sent,
            packets_received=packets_received,
            packets_lost=packets_lost,
            min_time=min(response_times) if response_times else 0,
            max_time=max(response_times) if response_times else 0,
            avg_time=statistics.mean(response_times) if response_times else 0,
            median_time=statistics.median(response_times) if response_times else 0,
            stddev_time=statistics.stdev(response_times) if len(response_times) > 1 else 0,
            loss_percentage=(packets_lost / packets_sent * 100) if packets_sent > 0 else 0,
            status_codes=status_codes,
            start_time=self.start_time,
            end_time=self.end_time or datetime.now()
        )

    def print_statistics(self, stats: SIPStats):
        console.print("\n")
        console.print(Panel(
            f"[bold cyan]SIP OPTIONS Test Results[/bold cyan]\n"
            f"Host: [green]{self.host}:{self.port}[/green] ({self.protocol.upper()})",
            style="bold"
        ))
        
        # Print statistics table
        console.print(self.create_stats_table(stats))
        
        # Print status codes table if we have responses
        if stats.packets_received > 0:
            console.print("\n")
            console.print(self.create_status_codes_table(stats))

    async def _send_options_async(self, sequence: int) -> Optional[SIPResponse]:
        try:
            if self.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:  # tcp
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(self.timeout)
            
            message = self._generate_options_request(sequence)
            start_time = time.time()
            self.logger.info(message)
            self.logger.info(message.encode())
            
            if self.protocol == 'tcp':
                await asyncio.get_event_loop().sock_connect(sock, (self.host, self.port))
                await asyncio.get_event_loop().sock_sendall(sock, message.encode())
            
            elif self.protocol == 'udp':
                await asyncio.get_event_loop().sock_sendto(sock, message.encode(), (self.host, self.port))
            
            if self.protocol == 'udp':
                response, _ = await asyncio.get_event_loop().sock_recvfrom(sock, 4096)
            else:
                response = await asyncio.get_event_loop().sock_recv(sock, 4096)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            response_str = response.decode('utf-8', errors='ignore')
            return self._parse_response(response_str, response_time, sequence)
            
        except socket.timeout:
            self.logger.warning(f"[yellow]Timeout after {self.timeout} seconds (sequence {sequence})[/yellow]")
            return None
        except Exception as e:
            self.logger.error(f"[red]Error sending OPTIONS (sequence {sequence}): {str(e)}[/red]")
            return None
        finally:
            sock.close()

    async def run(self) -> SIPStats:
        self.start_time = datetime.now()
        sequence = 1
        
        with self._create_progress() as progress:
            task = progress.add_task(
                f"[cyan]Sending OPTIONS requests to {self.host}:{self.port}...",
                total=self.count
            )
            
            try:
                while sequence <= self.count and not self.interrupted:
                    response = await self._send_options_async(sequence)
                    self.logger.info(response)
                    self.responses.append(response)
                    
                    if response:
                        progress.print(
                            f"[green]Response: {response.status_code} {response.status_message} "
                            f"time={response.response_time * 1000:.2f}ms[/green]"
                        )
                    
                    progress.update(task, advance=1)
                    
                    if sequence < self.count and not self.interrupted:
                        await asyncio.sleep(self.interval)
                    
                    sequence += 1
                    
            finally:
                self.end_time = datetime.now()
                stats = self.calculate_statistics()
                self.print_statistics(stats)
                return stats

async def save_stats_to_file(stats: SIPStats, filename: str):
    with open(filename, 'w') as f:
        json.dump(stats.to_dict(), f, indent=2)
    console.print(f"\n[green]Statistics saved to {filename}[/green]")

def main():
    parser = argparse.ArgumentParser(
        description='[bold cyan]SIP OPTIONS Tester[/bold cyan]',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('host', help='SIP host to test')
    parser.add_argument('port', type=int, help='SIP port')
    parser.add_argument('-c', '--count', type=int, default=4,
                       help='Number of packets to send (default: 4)')
    parser.add_argument('-t', '--timeout', type=int, default=3,
                       help='Timeout in seconds (default: 3)')
    parser.add_argument('-p', '--protocol', choices=['udp', 'tcp'],
                       default='udp', help='Protocol (default: udp)')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                       help='Interval between packets in seconds (default: 1.0)')
    parser.add_argument('-o', '--output', help='Output file for statistics (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose mode')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger('SIPOptionsTester').setLevel(logging.DEBUG)
    
    console.print(Panel.fit(
        "[bold cyan]SIP OPTIONS Tester[/bold cyan]\n"
        f"Target: [green]{args.host}:{args.port}[/green]",
        title="Configuration",
        style="bold"
    ))
    
    tester = SIPOptionsTester(
        args.host, args.port, args.count,
        args.timeout, args.protocol, args.interval
    )
    
    try:
        stats = asyncio.run(tester.run())
        
        if args.output:
            asyncio.run(save_stats_to_file(stats, args.output))
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)

if __name__ == '__main__':
    main()